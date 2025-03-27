package rhel

import (
	"context"
	"errors"
	"fmt"
	"runtime/trace"
	"slices"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/dnf"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/internal/wart"
)

var _ indexer.PackageScanner = PackageScanner{}

// PackageScanner implements a [indexer.PackageScanner] that consults both the
// rpm and dnf databases.
type PackageScanner struct{}

// Kind implements [indexer.PackageScanner].
func (p PackageScanner) Kind() string { return "package" }

// Name implements [indexer.PackageScanner].
func (p PackageScanner) Name() string { return "rhel-package-scanner" }

// Version implements [indexer.PackageScanner].
func (p PackageScanner) Version() string { return "1" }

// Scan implements [indexer.PackageScanner].
func (p PackageScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "PackageScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/PackageScanner.Scan",
		"version", p.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}

	found, err := rpm.FindDBs(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: error examining fs: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}

	zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")

	a, err := dnf.NewAnnotator(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: error examining fs: %w", err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error closing dnf Annotator")
		}
	}()
	if a == dnf.Identity {
		zlog.Debug(ctx).Msg("no dnf information found")
	}

	var final error
	seq := func(yield func(*claircore.Package) bool) {
		for _, db := range found {
			ctx := zlog.ContextWithValues(ctx, "db", db.String())
			zlog.Debug(ctx).Msg("examining database")

			seq, checkPkgs := db.Packages(ctx)
			seq, checkDNF := a.Wrap(ctx, seq)
			wart.AsPointer(seq)(yield)

			if err := errors.Join(checkDNF(), checkPkgs()); err != nil {
				final = fmt.Errorf("rhel: error reading native db: %w", err)
				return
			}
		}
	}

	return slices.Collect(seq), final
}
