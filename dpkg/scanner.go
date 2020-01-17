// Package dpkg implements a package indexer for dpkg packages.
package dpkg

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/rs/zerolog"
	"github.com/tadasv/go-dpkg"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const (
	name    = "dpkg"
	kind    = "package"
	version = "v0.0.1"
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
	trace.Log(ctx, "layer:sha256", layer.Hash)
	log := zerolog.Ctx(ctx).With().
		Str("component", "dpkg/Scanner.Scan").
		Str("version", ps.Version()).
		Str("layer", layer.Hash).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	// Grab a handle to the tarball, make sure we can seek.
	// If we can't, we'd need another reader for every database found.
	// It's cleaner to just demand that it's a seeker.
	rd, err := layer.Reader()
	if err != nil {
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}
	defer rd.Close()
	r, ok := rd.(io.ReadSeeker)
	if !ok {
		err := errors.New("unable to coerce to io.Seeker")
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}

	tr := tar.NewReader(r)
	// This is a map keyed by directory. A "score" of 2 means this is almost
	// certainly a dpkg database.
	loc := make(map[string]int)
Find:
	for {
		h, err := tr.Next()
		switch err {
		case nil:
		case io.EOF:
			break Find
		default:
			return nil, fmt.Errorf("reading next header failed: %w", err)
		}
		switch filepath.Base(h.Name) {
		case "status", "available":
			if h.Typeflag == tar.TypeReg {
				loc[filepath.Dir(h.Name)]++
			}
		}
	}
	log.Debug().Msg("scanned for possible databases")

	// If we didn't find anything, this loop is completely skipped.
	var pkgs []*claircore.Package
	for p, x := range loc {
		if x != 2 { // If we didn't find both files, skip this directory.
			continue
		}
		log := log.With().
			Str("database", p).
			Logger()
		log.Debug().Msg("examining package database")

		// Reset the tar reader.
		if n, err := r.Seek(0, io.SeekStart); n != 0 || err != nil {
			return nil, fmt.Errorf("unable to seek reader: %w", err)
		}
		tr = tar.NewReader(r)

		// We want the "status" file, so search the archive for it.
		fn := filepath.Join(p, "status")
		var db io.Reader
		var h *tar.Header
		for h, err = tr.Next(); err == nil; h, err = tr.Next() {
			if h.Name == fn {
				db = tr
				break
			}
		}
		// Check what happened in the above loop.
		switch {
		case err != nil:
			return nil, fmt.Errorf("reading status file from layer failed: %w", err)
		case db == nil:
			log.Error().
				Str("filename", fn).
				Msg("unable to get reader for file")
			panic("file existed, but now doesn't")
		}

		// Take all the packages found in the database and attach to the slice
		// defined outside the loop.
		found := make(map[string]*claircore.Package)
		for _, pkg := range dpkg.NewParser(db).Parse() {
			p := &claircore.Package{
				Name:      pkg.Package,
				Version:   pkg.Version,
				Kind:      "binary",
				PackageDB: fn,
			}
			if pkg.Source != "" {
				p.Source = &claircore.Package{
					Name: pkg.Source,
					Kind: "source",
					// Right now, this is an assumption that discovered source
					// packages relate to their binary versions. We see this in
					// Debian.
					Version:   pkg.Version,
					PackageDB: fn,
				}
			}

			found[p.Name] = p
			pkgs = append(pkgs, p)
		}

		// Reset the tar reader, again.
		if n, err := r.Seek(0, io.SeekStart); n != 0 || err != nil {
			return nil, fmt.Errorf("resetting tar reader failed: %w", err)
		}
		tr = tar.NewReader(r)
		prefix := filepath.Join(p, "info")
		const suffix = ".md5sums"
		for h, err = tr.Next(); err == nil; h, err = tr.Next() {
			if !strings.HasPrefix(h.Name, prefix) || !strings.HasSuffix(h.Name, suffix) {
				continue
			}
			n := filepath.Base(h.Name)
			n = strings.TrimSuffix(n, suffix)
			if i := strings.IndexRune(n, ':'); i != -1 {
				n = n[:i]
			}
			hash := md5.New()
			if _, err := io.Copy(hash, tr); err != nil {
				log.Warn().
					Err(err).
					Str("package", n).
					Msg("unable to read package metadata")
				continue
			}
			found[n].RepositoryHint = hex.EncodeToString(hash.Sum(nil))
		}
		log.Debug().
			Int("count", len(found)).
			Msg("found packages")
	}

	return pkgs, nil
}
