// Package dpkg implements a package indexer for dpkg packages.
package dpkg

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/textproto"
	"path/filepath"
	"runtime/trace"
	"slices"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	name    = "dpkg"
	kind    = "package"
	version = "7"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// This looks for directories that look like dpkg databases and examines the
// "status" file it finds there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (ps *Scanner) Name() string { return name }

// Version implements scanner.VersionedScanner.
func (ps *Scanner) Version() string { return version }

// Kind implements scanner.VersionedScanner.
func (ps *Scanner) Kind() string { return kind }

// Scan attempts to find a dpkg database within the layer and read all of the
// installed packages it can find in the "status" file.
//
// It's expected to return (nil, nil) if there's no dpkg database in the layer.
//
// It does not respect any dpkg configuration files.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	// Preamble
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("dpkg: opening layer failed: %w", err)
	}

	// This is a map keyed by directory. A "score" of 2 means this is almost
	// certainly a dpkg database.
	loc := make(map[string]int)
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch dir, f := filepath.Split(p); {
		case f == "status" && !d.IsDir():
			loc[dir]++
		case f == "info" && d.IsDir():
			loc[dir]++
		}
		return nil
	}

	if err := fs.WalkDir(sys, ".", walk); err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "scanned for possible databases")

	// If we didn't find anything, this loop is completely skipped.
	var pkgs []*claircore.Package
	var found *packages
	for p, x := range loc {
		if x != 2 { // If we didn't find both files, skip this directory.
			continue
		}
		if found == nil {
			found = newPackages()
		} else {
			found.Reset()
		}
		err := loadDatabase(ctx, sys, p, found, &pkgs)
		switch {
		case err == nil:
		case errors.Is(err, errNotDpkgDB):
			slog.InfoContext(ctx, "skipping possible database", "reason", err)
		default:
			return nil, err
		}
	}

	// This shouldn't need to use the "Stable" variant, as Name+Version should
	// be unique.
	slices.SortFunc(pkgs, sortpkg)

	return pkgs, nil
}

// ErrNotDpkgDB is reported internally when a possible database makes it to the
// parsing stage but doesn't contain the correct data.
var errNotDpkgDB = errors.New("not a dpkg database")

type packages struct {
	bin map[string]*claircore.Package
	src map[string]*claircore.Package
}

func newPackages() *packages {
	// Guess at initial sizing.
	return &packages{
		bin: make(map[string]*claircore.Package, 1024),
		src: make(map[string]*claircore.Package, 1024),
	}
}

func (p *packages) Reset() {
	clear(p.bin)
	clear(p.src)
}

// Sortpkg is a function for [slices.SortFunc].
// Defined this way to make it usable in tests.
func sortpkg(a, b *claircore.Package) int {
	cmp := strings.Compare(a.Name, b.Name)
	if cmp == 0 {
		return strings.Compare(a.Version, b.Version)
	}
	return cmp
}

// LoadDatabase loads the "status" and "info" files in the indicated directory.
//
// "Found"is used for scratch space and results are appended to the slice pointed to by "out".
func loadDatabase(ctx context.Context, sys fs.FS, dir string, found *packages, out *[]*claircore.Package) error {
	slog.DebugContext(ctx, "examining package database")

	// We want the "status" file.
	fn := filepath.Join(dir, "status")
	db, err := sys.Open(fn)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		slog.DebugContext(ctx, "false positive", "filename", fn)
		return err
	default:
		return fmt.Errorf("reading status file from layer failed: %w", err)
	}

	// The database is actually an RFC822-like message with "\n\n"
	// separators, so don't be alarmed by the usage of the "net/textproto"
	// package here.
	tp := textproto.NewReader(bufio.NewReader(db))
	if err := parseStatus(ctx, found, fn, tp); err != nil {
		return fmt.Errorf("unable to parse status file %q: %w", fn, err)
	}

	const suffix = ".md5sums"
	ms, err := fs.Glob(sys, filepath.Join(dir, "info", "*"+suffix))
	if err != nil {
		panic(fmt.Sprintf("programmer error: %v", err))
	}
	hash := md5.New()
	for _, n := range ms {
		k := strings.TrimSuffix(filepath.Base(n), suffix)
		if i := strings.IndexRune(k, ':'); i != -1 {
			k = k[:i]
		}
		p, ok := found.bin[k]
		if !ok {
			slog.DebugContext(ctx, "extra metadata found, ignoring", "package", k)
			continue
		}
		f, err := sys.Open(n)
		if err != nil {
			return fmt.Errorf("unable to open file %q: %w", n, err)
		}
		hash.Reset()
		_, err = io.Copy(hash, f)
		f.Close()
		if err != nil {
			slog.WarnContext(ctx, "unable to read package metadata",
				"package", n,
				"reason", err)
			continue
		}
		p.RepositoryHint = hex.EncodeToString(hash.Sum(nil))
	}
	slog.DebugContext(ctx, "found packages", "count", len(found.bin))

	for _, pkg := range found.bin {
		*out = append(*out, pkg)
	}

	return nil
}

// ParseStatus parses the dpkg "status" file in "tp".
//
// A status file (apparently -- this doesn't seem to be documented) is
// double-newline separated [deb-control(5)] records.
//
// Packages are stored in "found".
//
// [deb-control(5)]: https://manpages.debian.org/unstable/dpkg-dev/deb-control.5.en.html
func parseStatus(ctx context.Context, found *packages, fn string, tp *textproto.Reader) error {
Restart:
	hdr, err := tp.ReadMIMEHeader()
	for ; err == nil && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
		var ok, installed bool
		for s := range strings.FieldsSeq(hdr.Get("Status")) {
			switch s {
			case "installed":
				installed = true
			case "ok":
				ok = true
			}
		}
		if !ok || !installed {
			continue
		}
		name := hdr.Get("Package")
		v := hdr.Get("Version")
		arch := hdr.Get("Architecture")

		// Is this a valid package?
		//
		// Per deb-control(5), these are the required fields.
		if name == "" || v == "" || arch == "" {
			// Is this file a vcpkg database?
			//
			// These are keys not used by dpkg, but used by vcpkg. Vcpkg is
			// documented to name this file "CONTROL", but it's been seen in the
			// wild named "status".
			//
			// See also: https://learn.microsoft.com/en-us/vcpkg/maintainers/control-files
			for _, k := range []string{`Port-Version`, `Default-Features`, `Feature`} {
				k = textproto.CanonicalMIMEHeaderKey(k)
				if _, exists := hdr[k]; exists {
					// No; signal this file should be ignored.
					return errNotDpkgDB
				}
			}
			// Probably; report there's an invalid package.
			return fmt.Errorf("dpkg: invalid package: missing required fields (Package: %q, Version: %q)", name, v)
		}

		p := &claircore.Package{
			Name:      name,
			Version:   v,
			Kind:      claircore.BINARY,
			Arch:      arch,
			PackageDB: fn,
		}
		if src := hdr.Get("Source"); src != "" {
			// This "Name (Version)" scheme is handled by dpkg-query(1), so we
			// do similar.
			name, ver, ok := strings.Cut(src, " ")
			if ok {
				ver = strings.Trim(ver, "()")
			} else {
				name = src
				ver = v
			}

			srcpkg, ok := found.src[name]
			if !ok {
				srcpkg = &claircore.Package{
					Name:      name,
					Kind:      claircore.SOURCE,
					Version:   ver,
					PackageDB: fn,
				}
				found.src[name] = srcpkg
			}
			p.Source = srcpkg
		} else {
			// If there's not an explicit source package listed, assume it's a
			// 1-to-1 mapping.
			p.Source = &claircore.Package{
				Name:      name,
				Kind:      claircore.SOURCE,
				Version:   v,
				PackageDB: fn,
			}
		}

		found.bin[name] = p
	}
	switch {
	case errors.Is(err, io.EOF):
	default:
		slog.WarnContext(ctx, "unable to read entry", "reason", err)
		goto Restart
	}
	return nil
}
