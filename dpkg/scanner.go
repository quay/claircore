// Package dpkg implements a package indexer for dpkg packages.
package dpkg

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/textproto"
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "dpkg/Scanner.Scan"),
		label.String("version", ps.Version()),
		label.String("layer", layer.Hash.String()))
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
		case "status":
			if h.Typeflag == tar.TypeReg {
				loc[filepath.Dir(h.Name)]++
			}
		case "info":
			if h.Typeflag == tar.TypeDir {
				loc[filepath.Dir(filepath.Dir(h.Name))]++
			}
		}
	}
	zlog.Debug(ctx).Msg("scanned for possible databases")

	// If we didn't find anything, this loop is completely skipped.
	var pkgs []*claircore.Package
	for p, x := range loc {
		if x != 2 { // If we didn't find both files, skip this directory.
			continue
		}
		ctx = baggage.ContextWithValues(ctx, label.String("database", p))
		zlog.Debug(ctx).Msg("examining package database")

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
			// The location from above is cleaned, so make sure to do that.
			if c := filepath.Clean(h.Name); c == fn {
				db = tr
				break
			}
		}
		// Check what happened in the above loop.
		switch {
		case errors.Is(err, io.EOF):
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("reading status file from layer failed: %w", err)
		case db == nil:
			zlog.Error(ctx).
				Str("filename", fn).
				Msg("unable to get reader for file")
			panic("file existed, but now doesn't")
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

		// Reset the tar reader, again.
		if n, err := r.Seek(0, io.SeekStart); n != 0 || err != nil {
			return nil, fmt.Errorf("resetting tar reader failed: %w", err)
		}
		tr = tar.NewReader(r)
		prefix := filepath.Join(p, "info") + string(filepath.Separator)
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
			p, ok := found[n]
			if !ok {
				zlog.Debug(ctx).
					Str("package", n).
					Msg("extra metadata found, ignoring")
				continue
			}
			hash := md5.New()
			if _, err := io.Copy(hash, tr); err != nil {
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
