package apk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	name    = "apk"
	version = "v0.0.1"
	kind    = "package"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner scans for packages in an apk database.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements indexer.VersionedScanner.
func (*Scanner) Name() string { return name }

// Version implements indexer.VersionedScanner.
func (*Scanner) Version() string { return version }

// Kind implements indexer.VersionedScanner.
func (*Scanner) Kind() string { return kind }

const installedFile = "lib/apk/db/installed"

// Scan examines a layer for an apk installation database, and extracts
// the packages listed there.
//
// A return of (nil, nil) is expected if there's no apk database.
func (*Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := slog.With(
		"version", version,
		"layer", layer.Hash.String())

	log.DebugContext(ctx, "start")
	defer log.DebugContext(ctx, "done")

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("apk: unable to open layer: %w", err)
	}
	b, err := fs.ReadFile(sys, installedFile)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		return nil, err
	}
	log.DebugContext(ctx, "found database")

	pkgs := []*claircore.Package{}
	srcs := make(map[string]*claircore.Package)

	// It'd be great if we could just use the textproto package here, but we
	// can't because the database "keys" are case sensitive, unlike MIME
	// headers. So, roll our own entry and header splitting.
	delim := []byte("\n\n")
	entries := bytes.SplitSeq(b, delim)
	for entry := range entries {
		if len(entry) == 0 {
			continue
		}
		p := claircore.Package{
			Kind:      claircore.BINARY,
			PackageDB: installedFile,
		}
		r := bytes.NewBuffer(entry)
		for line, err := r.ReadBytes('\n'); err == nil; line, err = r.ReadBytes('\n') {
			l := string(bytes.TrimSpace(line[2:]))
			switch line[0] {
			case 'P':
				p.Name = l
			case 'V':
				p.Version = l
			case 'c':
				p.RepositoryHint = l
			case 'A':
				p.Arch = l
			case 'o':
				if src, ok := srcs[l]; ok {
					p.Source = src
				} else {
					p.Source = &claircore.Package{
						Name: l,
						Kind: claircore.SOURCE,
					}
					if p.Version != "" {
						p.Source.Version = p.Version
					}
					srcs[l] = p.Source
				}
			}
		}
		pkgs = append(pkgs, &p)
	}
	log.DebugContext(ctx, "found packages", "count", len(pkgs))

	return pkgs, nil
}
