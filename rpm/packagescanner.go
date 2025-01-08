// Package rpm provides an [indexer.PackageScanner] for the rpm package manager.
package rpm

import (
	"context"
	"fmt"
	"runtime/trace"
	"slices"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/internal/wart"
)

const (
	pkgName    = "rpm"
	pkgKind    = "package"
	pkgVersion = "10"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the [indexer.PackageScanner] interface.
//
// This looks for directories that look like rpm databases and examines the
// files it finds there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements [indexer.VersionedScanner].
func (*Scanner) Name() string { return pkgName }

// Version implements [indexer.VersionedScanner].
func (*Scanner) Version() string { return pkgVersion }

// Kind implements [indexer.VersionedScanner].
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

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("rpm: unable to open layer: %w", err)
	}

	found, err := rpm.FindDBs(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rpm: error examining fs: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}

	zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")

	var final error
	seq := func(yield func(*claircore.Package) bool) {
		for _, db := range found {
			ctx := zlog.ContextWithValues(ctx, "db", db.String())
			zlog.Debug(ctx).Msg("examining database")

			seq, check := db.Packages(ctx)
			wart.AsPointer(seq)(yield)

			if err := check(); err != nil {
				final = fmt.Errorf("rpm: error reading native db: %w", err)
				return
			}
		}
	}

	return slices.Collect(seq), final
}
