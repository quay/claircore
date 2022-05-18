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
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

const (
	name    = "dpkg"
	kind    = "package"
	version = "4"
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

	// Grab a handle to the tarball, make sure we can seek.
	// If we can't, we'd need another reader for every database found.
	// It's cleaner to just demand that it's a seeker.
	rd, err := layer.Reader()
	if err != nil {
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("opening layer failed: %w", err)
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
	for p, x := range loc {
		if x != 2 { // If we didn't find both files, skip this directory.
			continue
		}
		ctx = zlog.ContextWithValues(ctx, "database", p)
		zlog.Debug(ctx).Msg("examining package database")

		// We want the "status" file.
		fn := filepath.Join(p, "status")
		db, err := sys.Open(fn)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			zlog.Debug(ctx).
				Str("filename", fn).
				Msg("false positive")
			continue
		default:
			return nil, fmt.Errorf("reading status file from layer failed: %w", err)
		}

		// Take all the packages found in the database and attach to the slice
		// defined outside the loop.
		found := make(map[string]*claircore.Package)
		// The database is actually an RFC822-like message with "\n\n"
		// separators, so don't be alarmed by the usage of the "net/textproto"
		// package here.
		tp := textproto.NewReader(bufio.NewReader(db))
	Restart:
		hdr, err := tp.ReadMIMEHeader()
		for ; err == nil && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
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
				p.Source = &claircore.Package{
					Name: src,
					Kind: claircore.SOURCE,
					// Right now, this is an assumption that discovered source
					// packages relate to their binary versions. We see this in
					// Debian.
					Version:   v,
					PackageDB: fn,
				}
			}

			found[name] = p
			pkgs = append(pkgs, p)
		}
		switch {
		case errors.Is(err, io.EOF):
		default:
			zlog.Warn(ctx).Err(err).Msg("unable to read entry")
			goto Restart
		}

		const suffix = ".md5sums"
		ms, err := fs.Glob(sys, filepath.Join(p, "info", "*"+suffix))
		if err != nil {
			// ???
			return nil, fmt.Errorf("resetting tar reader failed: %w", err)
		}
		hash := md5.New()
		for _, n := range ms {
			k := strings.TrimSuffix(filepath.Base(n), suffix)
			if i := strings.IndexRune(k, ':'); i != -1 {
				k = k[:i]
			}
			p, ok := found[k]
			if !ok {
				zlog.Debug(ctx).
					Str("package", k).
					Msg("extra metadata found, ignoring")
				continue
			}
			f, err := sys.Open(n)
			if err != nil {
				return nil, fmt.Errorf("unable to open file %q: %w", n, err)
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
			Int("count", len(found)).
			Msg("found packages")
	}

	return pkgs, nil
}
