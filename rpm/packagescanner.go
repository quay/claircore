// Package rpm provides an [indexer.PackageScanner] for the rpm package manager.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime/trace"

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
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) (out []*claircore.Package, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("rpm: unable to open layer: %w", err)
	}

	dbs, errFunc := rpm.FindDBs(ctx, sys)
	defer func() {
		err = errors.Join(err, errFunc())
	}()
	for db := range dbs {
		err = func() error {
			slog.DebugContext(ctx, "examining database", "db", db)
			db, dbErr := rpm.OpenDB(ctx, sys, db)
			switch {
			case dbErr == nil:
			case errors.Is(dbErr, fs.ErrNotExist):
				return nil
			default:
				return dbErr
			}
			defer db.Close()
			for pkg, pkgErr := range db.Packages(ctx) {
				if pkgErr != nil {
					return pkgErr
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
