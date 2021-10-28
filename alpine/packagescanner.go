package alpine

import (
	"bytes"
	"context"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/baggageutil"
	"github.com/quay/claircore/internal/indexer"
)

const (
	pkgName    = `apk`
	pkgVersion = `v0.0.1`
	pkgKind    = `package`
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
func (*Scanner) Name() string { return pkgName }

// Version implements indexer.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements indexer.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

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
	ctx = baggageutil.ContextWithValues(ctx,
		"component", "alpine/Scanner.Scan",
		"version", pkgVersion,
		"layer", layer.Hash.String())

	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	fs, err := layer.Files(installedFile)
	switch err {
	case nil:
	case claircore.ErrNotFound:
		return nil, nil
	default:
		return nil, err
	}
	b, ok := fs[installedFile]
	if !ok {
		return nil, nil
	}
	zlog.Debug(ctx).Msg("found database")

	pkgs := []*claircore.Package{}
	srcs := make(map[string]*claircore.Package)

	// It'd be great if we could just use the textproto package here, but we
	// can't because the database "keys" are case sensitive, unlike MIME
	// headers. So, roll our own entry and header splitting.
	var delim = []byte("\n\n")
	entries := bytes.Split(b.Bytes(), delim)
	for _, entry := range entries {
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
	zlog.Debug(ctx).Int("count", len(pkgs)).Msg("found packages")

	return pkgs, nil
}
