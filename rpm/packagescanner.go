// Package rpm provides an [indexer.PackageScanner] for the rpm package manager.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/rpm"
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
//
// Deprecated: In-tree [indexer.PackageScanner] implementations should almost
// certainly use the "internal/rpm" and "internal/dnf" packages.
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

	var out []*claircore.Package
	dbs, errFunc := rpm.FindDBs(ctx, sys)
	defer func() {
		err = errors.Join(err, errFunc())
	}()
	for db := range dbs {
		err = func() error {
			ctx := zlog.ContextWithValues(ctx, "db", db.String())
			zlog.Debug(ctx).Msg("examining database")
			db, err := rpm.OpenDB(ctx, sys, db)
			switch {
			case err == nil:
			case errors.Is(err, fs.ErrNotExist):
				return nil
			default:
				return err
			}
			defer db.Close()
			for pkg, err := range db.Packages(ctx) {
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

	return out, nil
}
