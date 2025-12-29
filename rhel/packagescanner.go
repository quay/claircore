package rhel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/dnf"
	"github.com/quay/claircore/internal/rpm"
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
//
// This implementation stores additional information needed to correlate with
// [claircore.Repository] values in the "RepositoryHint" field.
func (p PackageScanner) Scan(ctx context.Context, layer *claircore.Layer) (out []*claircore.Package, err error) {
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

	doDNFWrap := false
	cm, err := getContentManifest(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to get content manifest: %w", err)
	}
	doDNFWrap = cm == nil || cm.FromDNFHint

	found, errFunc := rpm.FindDBs(ctx, sys)
	defer func() {
		err = errors.Join(err, errFunc())
	}()
	for found := range found {
		err = func() error {
			ctx := zlog.ContextWithValues(ctx, "db", found.String())
			zlog.Debug(ctx).Msg("examining database")
			db, err := rpm.OpenDB(ctx, sys, found)
			switch {
			case err == nil:
			case errors.Is(err, fs.ErrNotExist):
				return nil
			default:
				return err
			}
			defer db.Close()
			var pkgs dnf.PackageSeq
			if doDNFWrap {
				pkgs, err = dnf.Wrap(ctx, sys, db.Packages(ctx))
				if err != nil {
					return err
				}
			} else {
				pkgs = db.Packages(ctx)
			}
			for pkg, err := range pkgs {
				if err != nil {
					return err
				}
				out = append(out, &pkg)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	return
}
