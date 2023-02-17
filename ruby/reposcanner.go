// Package ruby contains components for interrogating ruby packages in
// container layers.
package ruby

import (
	"context"
	"fmt"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

const repository = "rubygems"

var (
	_ indexer.VersionedScanner  = (*RepoScanner)(nil)
	_ indexer.RepositoryScanner = (*RepoScanner)(nil)

	Repository = claircore.Repository{
		Name: repository,
		URI:  "https://rubygems.org/gems/",
	}
)

type RepoScanner struct{}

// Name implements scanner.VersionedScanner.
func (*RepoScanner) Name() string { return "gem" }

// Version implements scanner.VersionedScanner.
func (*RepoScanner) Version() string { return "1" }

// Kind implements scanner.VersionedScanner.
func (*RepoScanner) Kind() string { return "repository" }

// Scan attempts to find gems and record the package information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (rs *RepoScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "RepoScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "ruby/RepoScanner.Scan",
		"version", rs.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("ruby: unable to open tar: %w", err)
	}

	gs, err := gems(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("ruby: failed to find gems: %w", err)
	}
	if len(gs) != 0 {
		// Just claim these came from rubygems.
		return []*claircore.Repository{&Repository}, nil
	}

	return nil, nil
}
