package rpm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/rpm/bdb"
	"github.com/quay/claircore/rpm/ndb"
	"github.com/quay/claircore/rpm/sqlite"
)

const (
	pkgName    = "rpm"
	pkgKind    = "package"
	pkgVersion = "8"
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
	defer r.Close()

	found := make([]foundDB, 0)
	sys, err := tarfs.New(r)
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

		var nat nativeDB // see native_db.go:/nativeDB
		switch db.Kind {
		case kindSQLite:
			r, err := sys.Open(path.Join(db.Path, `rpmdb.sqlite`))
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					zlog.Warn(ctx).Err(err).Msg("unable to close tarfs sqlite db")
				}
			}()
			f, err := os.CreateTemp(os.TempDir(), `rpmdb.sqlite.*`)
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
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
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
			}
			if err := f.Sync(); err != nil {
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
			}
			sdb, err := sqlite.Open(f.Name())
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
			}
			defer sdb.Close()
			nat = sdb
		case kindBDB:
			f, err := sys.Open(path.Join(db.Path, `Packages`))
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading bdb db: %w", err)
			}
			defer f.Close()
			r, done, err := mkAt(ctx, db.Kind, f)
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading bdb db: %w", err)
			}
			defer done()
			var bpdb bdb.PackageDB
			if err := bpdb.Parse(r); err != nil {
				return nil, fmt.Errorf("rpm: error parsing bdb db: %w", err)
			}
			nat = &bpdb
		case kindNDB:
			f, err := sys.Open(path.Join(db.Path, `Packages.db`))
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading ndb db: %w", err)
			}
			defer f.Close()
			r, done, err := mkAt(ctx, db.Kind, f)
			if err != nil {
				return nil, fmt.Errorf("rpm: error reading ndb db: %w", err)
			}
			defer done()
			var npdb ndb.PackageDB
			if err := npdb.Parse(r); err != nil {
				return nil, fmt.Errorf("rpm: error parsing ndb db: %w", err)
			}
			nat = &npdb
		default:
			panic("programmer error: bad kind: " + db.Kind.String())
		}
		ps, err := packagesFromDB(ctx, db.String(), nat)
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading native db: %w", err)
		}
		pkgs = append(pkgs, ps...)
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
		switch n {
		case `Packages`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := bdb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindBDB,
			})
		case `rpmdb.sqlite`:
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindSQLite,
			})
		case `Packages.db`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := ndb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindNDB,
			})
		}
		return nil
	}
}

func mkAt(ctx context.Context, k dbKind, f fs.File) (io.ReaderAt, func(), error) {
	if r, ok := f.(io.ReaderAt); ok {
		return r, func() {}, nil
	}
	spool, err := os.CreateTemp(os.TempDir(), `Packages.`+k.String()+`.`)
	if err != nil {
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}
	ctx = zlog.ContextWithValues(ctx, "file", spool.Name())
	if err := os.Remove(spool.Name()); err != nil {
		zlog.Error(ctx).Err(err).Msg("unable to remove spool; file leaked!")
	}
	zlog.Debug(ctx).
		Msg("copying db out of fs.FS")
	if _, err := io.Copy(spool, f); err != nil {
		if err := spool.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close spool")
		}
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}
	return spool, closeSpool(ctx, spool), nil
}

func closeSpool(ctx context.Context, f *os.File) func() {
	return func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close spool")
		}
	}
}

type dbKind uint

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    // bdb
	kindSQLite // sqlite
	kindNDB    // ndb
)

type foundDB struct {
	Path string
	Kind dbKind
}

func (f foundDB) String() string {
	return f.Kind.String() + ":" + f.Path
}
