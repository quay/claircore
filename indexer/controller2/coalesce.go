package controller

import (
	"context"
	"fmt"
	"reflect"
	"runtime/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Coalesce is the step that takes each configured Ecosystem, creates
// LayerArtifacts for all layers in the current Manifest, and then runs the
// ecosystem's Coalescer. The resulting IndexRecords are then merged
// and stored in the indexState.
func _Coalesce(ctx context.Context, s *indexState) stateFn {
	const errMsg = `controller: failed to retrieve %s for %v: %w`
	defer trace.StartRegion(ctx, "indexer/controller/Coalesce").End()
	reports := make([]*claircore.IndexReport, 0, len(s.Ecosystems))
	// dispatch a coalescer go routine for each ecosystem
	for _, ecosystem := range s.Ecosystems {
		artifacts := make([]indexer.LayerArtifacts, 0, len(s.Manifest.Layers))
		pkgScanners, err := ecosystem.PackageScanners(ctx)
		if err != nil {
			return s.error(ctx, fmt.Errorf("failed to get package indexers: %w", err))
		}
		distScanners, err := ecosystem.DistributionScanners(ctx)
		if err != nil {
			return s.error(ctx, fmt.Errorf("failed to get distribution indexers: %w", err))
		}
		repoScanners, err := ecosystem.RepositoryScanners(ctx)
		if err != nil {
			return s.error(ctx, fmt.Errorf("failed to get repository indexers: %w", err))
		}
		for _, layer := range s.Manifest.Layers {
			pkgs, err := s.Store.PackagesByLayer(ctx, layer.Hash, despecialize(pkgScanners))
			if err != nil {
				return s.error(ctx, fmt.Errorf(errMsg, "packages", layer.Hash, err))
			}
			dists, err := s.Store.DistributionsByLayer(ctx, layer.Hash, despecialize(distScanners))
			if err != nil {
				return s.error(ctx, fmt.Errorf(errMsg, "distributions", layer.Hash, err))
			}
			repos, err := s.Store.RepositoriesByLayer(ctx, layer.Hash, despecialize(repoScanners))
			if err != nil {
				return s.error(ctx, fmt.Errorf(errMsg, "repositories", layer.Hash, err))
			}
			// pack artifacts array in layer order
			artifacts = append(artifacts, indexer.LayerArtifacts{
				Hash:  layer.Hash,
				Pkgs:  pkgs,
				Dist:  dists,
				Repos: repos,
			})
		}
		coalescer, err := ecosystem.Coalescer(ctx)
		if err != nil {
			return s.error(ctx, fmt.Errorf("failed to get coalescer from ecosystem: %w", err))
		}

		c, ok := coalescer.(coalescerNext)
		if !ok {
			c = pointerfyArtifacts(coalescer.Coalesce)
		}
		ir, err := c.CoalesceNext(ctx, artifacts)
		if err != nil {
			return s.error(ctx, err)
		}

		reports = append(reports, ir)
	}
	for _, r := range reports {
		merge(s.Out, r)
	}
	return _IndexManifest
}

// CoalescerNext is a prototype for a new Coalescer interface.
//
// If this interface is implemented by the Coalescer, it will be used
// instead of the Coalescer interface.
type coalescerNext interface {
	CoalesceNext(context.Context, []indexer.LayerArtifacts) (*claircore.IndexReport, error)
}

// PointerfyArtifacts translates the method of a [indexer.Coaleser] into
// the prototype [coalescerNext] interface.
type pointerfyArtifacts func(context.Context, []*indexer.LayerArtifacts) (*claircore.IndexReport, error)

// CoalesceNext implements [CoalescerNext].
func (p pointerfyArtifacts) CoalesceNext(ctx context.Context, as []indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ptrs := make([]*indexer.LayerArtifacts, len(as))
	for i := range as {
		ptrs[i] = &as[i]
	}
	return p(ctx, ptrs)
}

// Despecialize translates a slice of narrowed scanner interfaces into the
// broad interface.
func despecialize[T indexer.VersionedScanner](in []T) []indexer.VersionedScanner {
	out := make([]indexer.VersionedScanner, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// Merge merges the contents of "src" into "dst", modifying "dst".
func merge(dst *claircore.IndexReport, src *claircore.IndexReport) {
	for k, v := range src.Environments {
		if envs, ok := dst.Environments[k]; ok {
		New:
			for _, new := range v {
				for _, env := range envs {
					if reflect.DeepEqual(env, new) {
						dst.Environments[k] = append(envs, new)
						continue New
					}
				}
			}
			continue
		}
		dst.Environments[k] = v
	}
	for k, v := range src.Packages {
		dst.Packages[k] = v
	}
	for k, v := range src.Distributions {
		dst.Distributions[k] = v
	}
	for k, v := range src.Repositories {
		dst.Repositories[k] = v
	}
}
