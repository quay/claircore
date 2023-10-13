// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"context"
	"fmt"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	_ indexer.VersionedScanner  = (*RepoScanner)(nil)
	_ indexer.RepositoryScanner = (*RepoScanner)(nil)

	Repository = claircore.Repository{
		Name: "pypi",
		URI:  "https://pypi.org/simple",
	}
)

type RepoScanner struct{}

// Name implements scanner.VersionedScanner.
func (*RepoScanner) Name() string { return "pip" }

// Version implements scanner.VersionedScanner.
func (*RepoScanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*RepoScanner) Kind() string { return "repository" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (rs *RepoScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "RepoScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "python/RepoScanner.Scan",
		"version", rs.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("python: unable to open layer: %w", err)
	}

	ms, err := findDeliciousEgg(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("python: failed to find delicious egg: %w", err)
	}
	if len(ms) != 0 {
		// Just claim these came from pypi.
		return []*claircore.Repository{&Repository}, nil
	}

	return nil, nil
}
