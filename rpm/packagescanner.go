package rpm

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/trace"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/rpm/sqlite"
)

const (
	pkgName    = "rpm"
	pkgKind    = "package"
	pkgVersion = "5"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// This looks for directories that look like rpm databases and examines the
// files it finds there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return pkgName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

// Scan attempts to find rpm databases within the layer and enumerate the
// packages there.
//
// A return of (nil, nil) is expected if there's no rpm database.
//
// The external command "rpm" is used and expected to be in PATH.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "rpm/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
		io.ReaderAt
	})
	if !ok {
		return nil, errors.New("rpm: cannot seek on returned layer Reader")
	}

	found := make([]foundDB, 0)
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("rpm: unable to create tarfs: %w", err)
	}
	if err := fs.WalkDir(sys, ".", findDBs(ctx, &found, sys)); err != nil {
		return nil, fmt.Errorf("rpm: error walking fs: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}

	zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")

	var (
		extractRoot string
		extractErr  error
		extractOnce sync.Once
	)
	defer func() {
		if extractRoot == "" {
			return
		}
		if err := os.RemoveAll(extractRoot); err != nil {
			// Raising an error should notify an operator?
			//
			// It's this or panic.
			zlog.Error(ctx).Err(err).Msg("error removing extracted files")
		}
	}()

	var pkgs []*claircore.Package
	done := map[string]struct{}{}
	for _, db := range found {
		ctx := zlog.ContextWithValues(ctx, "db", db.String())
		zlog.Debug(ctx).Msg("examining database")
		if _, ok := done[db.Path]; ok {
			zlog.Debug(ctx).Msg("already seen, skipping")
			continue
		}
		done[db.Path] = struct{}{}

		switch db.Kind {
		case kindNDB:
			fallthrough
		case kindBDB:
			extractOnce.Do(func() { extractRoot, extractErr = extractTar(ctx, rd) })
			if err := extractErr; err != nil {
				return nil, err
			}
			// Using --root and --dbpath, run rpm query on every suspected database.
			// RPM interprets the absolute path passed to "dbpath" as underneath "root".
			cmd := exec.CommandContext(ctx, "rpm",
				`--root`, extractRoot, `--dbpath`, filepath.Join("/", db.Path),
				`--query`, `--all`, `--queryformat`, queryFmt)
			r, err := cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}
			errbuf := bytes.Buffer{}
			cmd.Stderr = &errbuf
			zlog.Debug(ctx).Strs("cmd", cmd.Args).Msg("rpm invocation")
			if err := cmd.Start(); err != nil {
				r.Close()
				return nil, err
			}
			// Use a closure to defer the Close call.
			if err := func() error {
				defer r.Close()
				srcs := make(map[string]*claircore.Package)
				s := bufio.NewScanner(r)
				s.Split(querySplit)

				for s.Scan() {
					p, err := parsePackage(ctx, srcs, bytes.NewBuffer(s.Bytes()))
					if err != nil {
						return err
					}
					p.PackageDB = db.String()
					pkgs = append(pkgs, p)
				}

				return s.Err()
			}(); err != nil {
				if errbuf.Len() != 0 {
					zlog.Warn(ctx).
						Strs("cmd", cmd.Args).
						Str("err", errbuf.String()).
						Msg("error output")
				}
				return nil, fmt.Errorf("rpm: error reading rpm output: %w", err)
			}
			if err := cmd.Wait(); err != nil {
				return nil, err
			}
		case kindSQLite:
			if err := func() error {
				r, err := sys.Open(path.Join(db.Path, `rpmdb.sqlite`))
				if err != nil {
					return err
				}
				defer func() {
					if err := r.Close(); err != nil {
						zlog.Warn(ctx).Err(err).Msg("unable to close tarfs sqlite db")
					}
				}()
				f, err := os.CreateTemp(os.TempDir(), `rpmdb.sqlite.*`)
				if err != nil {
					return err
				}
				defer func() {
					if err := os.Remove(f.Name()); err != nil {
						zlog.Error(ctx).Err(err).Msg("unable to unlink sqlite db")
					}
					if err := f.Close(); err != nil {
						zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db")
					}
				}()
				zlog.Debug(ctx).Str("file", f.Name()).Msg("copying sqlite db out of tar")
				if _, err := io.Copy(f, r); err != nil {
					return err
				}
				if err := f.Sync(); err != nil {
					return err
				}
				rpm, err := sqlite.Open(f.Name())
				if err != nil {
					return err
				}
				defer rpm.Close()
				infos, err := rpm.Packages(ctx)
				if err != nil {
					return err
				}
				ps, err := packagesFromInfos(ctx, db.String(), infos)
				if err != nil {
					return err
				}
				pkgs = append(pkgs, ps...)
				return nil
			}(); err != nil {
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
			}
		default:
			panic("programmer error")
		}
	}

	return pkgs, nil
}

func findDBs(ctx context.Context, out *[]foundDB, sys fs.FS) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		dir, n := path.Split(p)
		dir = path.Clean(dir)
		switch {
		case n == "Packages.db": // ndb specfic
			fallthrough
		case n == `Packages`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if !checkMagic(ctx, f) {
				return nil
			}
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindBDB,
			})
		case n == `rpmdb.sqlite`:
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindSQLite,
			})
		}
		return nil
	}
}

// RelPath takes a member and forcibly interprets it as a path underneath root.
//
// This should be used anytime a path for a new file on disk is needed when
// unpacking a tar.
func relPath(root, member string) string {
	return filepath.Join(root, filepath.Join("/", member))
}

type dbKind uint

//go:generate stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    //bdb
	kindSQLite //sqlite
	kindNDB    //ndb
)

type foundDB struct {
	Path string
	Kind dbKind
}

func (f foundDB) String() string {
	return f.Kind.String() + ":" + f.Path
}
