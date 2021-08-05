package rpm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const (
	pkgName    = "rpm"
	pkgKind    = "package"
	pkgVersion = "v0.0.2"
)

// DbNames is a set of files that make up an rpm database.
var dbnames = map[string]struct{}{
	"Packages": {},
}

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
// The external commands "tar" and "rpm" are used and expected to be in PATH.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "rpm/Scanner.Scan"),
		label.String("version", ps.Version()),
		label.String("layer", layer.Hash.String()))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("rpm: cannot seek on returned layer Reader")
	}

	// Map of directory to confidence score. Confidence of len(dbnames) means
	// it's almost certainly an rpm database.
	possible := make(map[string]int)
	tr := tar.NewReader(rd)
	// Find possible rpm dbs
	// If none found, return
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n := filepath.Base(h.Name)
		d := filepath.Dir(h.Name)
		if _, ok := dbnames[n]; ok {
			possible[d]++
		}
	}
	if err != io.EOF {
		return nil, err
	}
	if len(possible) == 0 {
		return nil, nil
	}
	found := make([]string, 0)
	for k, score := range possible {
		if score == len(dbnames) {
			found = append(found, filepath.Join("/", k))
		}
	}
	zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")
	if len(found) == 0 {
		return nil, nil
	}

	root, err := ioutil.TempDir("", "rpmscanner.")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			// Raising an error should notify an operator?
			//
			// It's this or panic.
			zlog.Error(ctx).Err(err).Msg("error removing extracted files")
		}
	}()
	// Extract tarball
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := rd.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rpm: unable to seek: %w", err)
	}
	// Using an external tar (probably GNU tar) works where things like
	// docker/docker's pkg/archive don't because it seems to set directory
	// permissions later. Otherwise, some layers will have directories without
	// the write bit created and the permissions set before their contents are
	// created.
	errbuf := bytes.Buffer{}
	// Unprivileged containers can't call mknod(2), so exclude /dev and
	// hopefully there aren't any others strewn about.
	tarcmd := exec.CommandContext(ctx, "tar",
		"--extract",
		"--exclude", "dev",
		"--exclude", ".wh*",
		"--delay-directory-restore",
		"--no-same-owner",
		"--no-same-permissions",
	)
	tarcmd.Stdin = rd
	tarcmd.Stderr = &errbuf
	tarcmd.Dir = root
	zlog.Debug(ctx).Str("dir", root).Strs("cmd", tarcmd.Args).Msg("tar invocation")
	if err := tarcmd.Run(); err != nil {
		zlog.Error(ctx).
			Str("dir", root).
			Strs("cmd", tarcmd.Args).
			Stringer("stderr", &errbuf).
			AnErr("err", err).
			Msg("error extracting layer")
		return nil, fmt.Errorf("rpm: failed to untar: %w", err)
	}
	zlog.Debug(ctx).Str("dir", root).Msg("extracted layer")
	// Immediately fix permissions.
	if err := filepath.Walk(root, fixDirs(ctx)); err != nil {
		if rmerr := os.RemoveAll(root); rmerr != nil {
			err = fmt.Errorf("%v (and during cleanup: %v)", err, rmerr)
		}
		return nil, fmt.Errorf("rpm: failed to change permissions: %w", err)
	}

	var pkgs []*claircore.Package
	// Using --root and --dbpath, run rpm query on every suspected database
	for _, db := range found {
		zlog.Debug(ctx).Str("db", db).Msg("examining database")

		cmd := exec.CommandContext(ctx, "rpm",
			`--root`, root, `--dbpath`, db,
			`--query`, `--all`, `--queryformat`, queryFmt)
		r, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		errbuf := bytes.Buffer{}
		cmd.Stderr = &errbuf
		zlog.Debug(ctx).Str("db", db).Strs("cmd", cmd.Args).Msg("rpm invocation")
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
				p.PackageDB = db
				pkgs = append(pkgs, p)
			}

			return s.Err()
		}(); err != nil {
			if errbuf.Len() != 0 {
				zlog.Warn(ctx).
					Str("db", db).
					Strs("cmd", cmd.Args).
					Str("err", errbuf.String()).
					Msg("error output")
			}
			return nil, fmt.Errorf("rpm: error reading rpm output: %w", err)
		}
		if err := cmd.Wait(); err != nil {
			return nil, err
		}
	}

	return pkgs, nil
}

// FixDirs forces every directory to be u+w.
//
// The closed-over Context is used for logging.
func fixDirs(ctx context.Context) filepath.WalkFunc {
	// TODO(hank) 1.16+: Port to using fs.WalkDir, which is faster because it
	// doesn't produce a FileInfo while walking.
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Str("path", path).
				Interface("info", info).
				Msg("error walking extracted layer")
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		return os.Chmod(path, info.Mode()|0700)
	}
}

// This is the query format we're using to get data out of rpm.
//
// There's XML output, but it's all jacked up.
const queryFmt = `%{name}\n` +
	`%{evr}\n` +
	`%{payloaddigestalgo}:%{payloaddigest}\n` +
	`%{sigpgp:pgpsig}\n` +
	`%{sourcerpm}\n` +
	`%{RPMTAG_MODULARITYLABEL}\n` +
	`%{ARCH}\n` +
	`.\n`
const delim = "\n.\n"

func querySplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.Index(data, []byte(delim))
	switch {
	case len(data) == 0 && atEOF:
		return 0, nil, io.EOF
	case i == -1 && atEOF:
		return 0, nil, errors.New("invalid format")
	case i == -1 && !atEOF:
		return 0, nil, nil
	default:
	}
	tok := data[:i]
	return len(tok) + len(delim), tok, nil
}

func parsePackage(ctx context.Context, src map[string]*claircore.Package, buf *bytes.Buffer) (*claircore.Package, error) {
	defer trace.StartRegion(ctx, "parsePackage").End()
	p := claircore.Package{
		Kind: claircore.BINARY,
	}
	var err error
	var line string

	for i := 0; ; i++ {
		// Look at the "queryFmt" string for the line numbers.
		line, err = buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(none)") {
			continue
		}
		if line == "" && err == nil {
			zlog.Info(ctx).
				Str("package", p.Name).
				Int("lineno", i).
				Msg("unexpected empty line")
			continue
		}
		switch i {
		case 0:
			p.Name = line
		case 1:
			p.Version = line
		case 2:
			p.RepositoryHint = "hash:"
			switch line[0] {
			case '8': // sha256
				p.RepositoryHint += "sha256" + line[1:]
			}
		case 3:
			const delim = `Key ID `
			i := strings.Index(line, delim)
			if i == -1 { // ???
				break
			}
			p.RepositoryHint += "|key:" + line[i+len(delim):]
		case 4:
			line = strings.TrimSuffix(line, ".src.rpm")
			sp := strings.Split(line, "-")
			name := strings.Join(sp[:len(sp)-2], "-")
			if s, ok := src[name]; ok {
				p.Source = s
				break
			}
			p.Source = &claircore.Package{
				Name:    name,
				Version: sp[len(sp)-2] + "-" + sp[len(sp)-1],
				Kind:    claircore.SOURCE,
			}
			src[name] = p.Source
		case 5:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
			if p.Source != nil {
				p.Source.Module = moduleStream
			}
		case 6:
			p.Arch = line
		}
		switch err {
		case nil:
		case io.EOF:
			return &p, nil
		default:
			return nil, err
		}
	}
}
