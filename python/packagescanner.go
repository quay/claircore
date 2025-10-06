// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/textproto"
	"path"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/rpm"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: "pypi",
		URI:  "https://pypi.org/simple",
	}
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there. This type attempts to follow the specs documented by
// the [PyPA], with the newer PEPs being preferred.
//
// The zero value is ready to use.
//
// [PyPA]: https://packaging.python.org/en/latest/specifications/recording-installed-packages/
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "python" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "5" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("python: unable to open layer: %w", err)
	}

	ms, err := findDeliciousEgg(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("python: failed to find delicious egg: %w", err)
	}
	var ret []*claircore.Package
	set, err := rpm.NewPathSet(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("python: unable to check RPM db: %w", err)
	}
	for _, n := range ms {
		if set.Contains(n) {
			slog.DebugContext(ctx, "file path determined to be of RPM origin", "path", n)
			continue
		}
		b, err := fs.ReadFile(sys, n)
		if err != nil {
			return nil, fmt.Errorf("python: unable to read file: %w", err)
		}
		// The two files we read are in RFC8288 (email message) format, and the
		// keys we care about are shared.
		rd := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
		hdr, err := rd.ReadMIMEHeader()
		if err != nil && hdr == nil {
			slog.WarnContext(ctx, "unable to read metadata, skipping", "reason", err, "path", n)
			continue
		}
		v, err := pep440.Parse(hdr.Get("Version"))
		if err != nil {
			slog.WarnContext(ctx, "couldn't parse the version, skipping", "reason", err, "path", n)
			continue
		}
		pkgDB := filepath.Join(n, "..", "..")
		// If the package is .egg-info format
		// with just the .egg-info file,
		// only go up one level.
		if strings.HasSuffix(n, `.egg-info`) {
			pkgDB = filepath.Join(n, "..")
		}
		ret = append(ret, &claircore.Package{
			Name:              strings.ToLower(hdr.Get("Name")),
			Version:           v.String(),
			PackageDB:         "python:" + pkgDB,
			Filepath:          n,
			Kind:              claircore.BINARY,
			NormalizedVersion: v.Version(),
			// TODO Is there some way to pick up on where a wheel or egg was
			// found?
			RepositoryHint: "https://pypi.org/simple",
		})
	}
	return ret, nil
}

// DefaultRepository implements [indexer.DefaultRepoScanner]
func (Scanner) DefaultRepository(ctx context.Context) *claircore.Repository {
	return &Repository
}

// findDeliciousEgg finds eggs and wheels.
//
// Three formats are supported at this time:
//
// * .egg      - only when .egg is a directory. .egg as a zipfile is not supported at this time.
// * .egg-info - both as a standalone file and a directory which contains PKG-INFO.
// * wheel     - only .dist-info/METADATA is supported.
//
// See https://setuptools.pypa.io/en/latest/deprecated/python_eggs.html for more information about Python Eggs
// and https://peps.python.org/pep-0427/ for more information about Wheel.
func findDeliciousEgg(ctx context.Context, sys fs.FS) (out []string, err error) {
	// Is this layer an rpm layer?
	//
	// If so, files in the disto-managed directory can be skipped.
	var isRPM bool
	for _, p := range []string{
		"var/lib/rpm/Packages",
		"var/lib/rpm/rpmdb.sqlite",
		"var/lib/rpm/Packages.db",
	} {
		if fi, err := fs.Stat(sys, p); err == nil && fi.Mode().IsRegular() {
			isRPM = true
			break
		}
	}
	// Is this layer a dpkg layer?
	var dpkg bool
	if fi, err := fs.Stat(sys, `var/lib/dpkg/status`); err == nil && fi.Mode().IsRegular() {
		dpkg = true
	}

	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		attrs := []slog.Attr{slog.String("file", p)}
		switch {
		case err != nil:
			return err
		case (isRPM || dpkg) && d.Type().IsDir():
			// Skip one level up from the "packages" directory so the walk also
			// skips the standard library.
			var pat string
			switch {
			case isRPM:
				pat = `usr/lib*/python[23].*`
				attrs = append(attrs, slog.Bool("rpm_dir", true))
			case dpkg:
				pat = `usr/lib*/python[23]`
				attrs = append(attrs, slog.Bool("dpkg_dir", true))
			default:
				panic("programmer error: unreachable")
			}
			if m, _ := path.Match(pat, p); m {
				slog.LogAttrs(ctx, slog.LevelDebug, "skipping directory", attrs...)
				return fs.SkipDir
			}
			fallthrough
		case !d.Type().IsRegular():
			// Should we chase symlinks with the correct name?
			return nil
		case strings.HasPrefix(filepath.Base(p), ".wh."):
			return nil
		case strings.HasSuffix(p, `.egg/EGG-INFO/PKG-INFO`):
			attrs = append(attrs, slog.String("kind", ".egg"))
		case strings.HasSuffix(p, `.egg-info`):
			fallthrough
		case strings.HasSuffix(p, `.egg-info/PKG-INFO`):
			attrs = append(attrs, slog.String("kind", ".egg-info"))
		case strings.HasSuffix(p, `.dist-info/METADATA`):
			attrs = append(attrs, slog.String("kind", "wheel"))
			// See if we can discern the installer.
			var installer string
			ip := path.Join(path.Dir(p), `INSTALLER`)
			if ic, err := fs.ReadFile(sys, ip); err == nil {
				installer = string(bytes.TrimSpace(ic))
				attrs = append(attrs, slog.String("installer", installer))
			}
			if _, ok := blocklist[installer]; ok {
				slog.LogAttrs(ctx, slog.LevelDebug, "skipping package", attrs...)
				return nil
			}
		default:
			return nil
		}
		slog.LogAttrs(ctx, slog.LevelDebug, "found package", attrs...)
		out = append(out, p)
		return nil
	})
}

// Blocklist of installers to ignore.
//
// Currently, rpm is the only known package manager that actually populates this
// information.
var blocklist = map[string]struct{}{
	"rpm":  {},
	"dpkg": {},
	"apk":  {},
}
