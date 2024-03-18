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
	"net/textproto"
	"path/filepath"
	"runtime/trace"
	"slices"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	name    = "dpkg"
	kind    = "package"
	version = "6"
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
	ctx = zlog.ContextWithValues(ctx,
		"component", "dpkg/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

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
	zlog.Debug(ctx).Msg("scanned for possible databases")

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
		if err := loadDatabase(ctx, sys, p, found, &pkgs); err != nil {
			return nil, err
		}
	}

	// This shouldn't need to use the "Stable" variant, as Name+Version should
	// be unique.
	slices.SortFunc(pkgs, sortpkg)

	return pkgs, nil
}

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
	zlog.Debug(ctx).Msg("examining package database")

	// We want the "status" file.
	fn := filepath.Join(dir, "status")
	db, err := sys.Open(fn)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).
			Str("filename", fn).
			Msg("false positive")
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
			zlog.Debug(ctx).
				Str("package", k).
				Msg("extra metadata found, ignoring")
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
			zlog.Warn(ctx).
				Err(err).
				Str("package", n).
				Msg("unable to read package metadata")
			continue
		}
		p.RepositoryHint = hex.EncodeToString(hash.Sum(nil))
	}
	zlog.Debug(ctx).
		Int("count", len(found.bin)).
		Msg("found packages")

	for _, pkg := range found.bin {
		*out = append(*out, pkg)
	}

	return nil
}

// ParseStatus parses the dpkg "status" file in "tp".
//
// Packages are stored in "found".
func parseStatus(ctx context.Context, found *packages, fn string, tp *textproto.Reader) error {
Restart:
	hdr, err := tp.ReadMIMEHeader()
	for ; err == nil && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
		var ok, installed bool
		for _, s := range strings.Fields(hdr.Get("Status")) {
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
		p := &claircore.Package{
			Name:      name,
			Version:   v,
			Kind:      claircore.BINARY,
			Arch:      hdr.Get("Architecture"),
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
		zlog.Warn(ctx).Err(err).Msg("unable to read entry")
		goto Restart
	}
	return nil
}
