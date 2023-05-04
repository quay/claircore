package controller

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// coalesce calls each ecosystem's coalescer and merges the returned IndexReports
func coalesce(ctx context.Context, s *Controller) (State, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mu := sync.Mutex{}
	reports := []*claircore.IndexReport{}
	g := errgroup.Group{}
	// dispatch a coalescer go routine for each ecosystem
	for _, ecosystem := range s.Ecosystems {
		artifacts := []*indexer.LayerArtifacts{}
		pkgScanners, _ := ecosystem.PackageScanners(cctx)
		distScanners, _ := ecosystem.DistributionScanners(cctx)
		repoScanners, _ := ecosystem.RepositoryScanners(cctx)
		fileScanners := []indexer.FileScanner{}
		if ecosystem.FileScanners != nil {
			fileScanners, _ = ecosystem.FileScanners(cctx)
		}
		// pack artifacts var
		for _, layer := range s.manifest.Layers {
			la := &indexer.LayerArtifacts{
				Hash: layer.Hash,
			}
			var vscnrs indexer.VersionedScanners
			vscnrs.PStoVS(pkgScanners)
			// get packages from layer
			pkgs, err := s.Store.PackagesByLayer(cctx, layer.Hash, vscnrs)
			if err != nil {
				// on an early return cctx is canceled, and all inflight coalescers are canceled as well
				return Terminal, fmt.Errorf("failed to retrieve packages for %v: %w", layer.Hash, err)
			}
			la.Pkgs = append(la.Pkgs, pkgs...)
			// get distributions from layer
			vscnrs.DStoVS(distScanners) // method allocates new vscnr underlying array, clearing old contents
			dists, err := s.Store.DistributionsByLayer(cctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve distributions for %v: %w", layer.Hash, err)
			}
			la.Dist = append(la.Dist, dists...)
			// get repositories from layer
			vscnrs.RStoVS(repoScanners)
			repos, err := s.Store.RepositoriesByLayer(cctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve repositories for %v: %w", layer.Hash, err)
			}
			la.Repos = append(la.Repos, repos...)
			// get files from layer
			vscnrs.FStoVS(fileScanners)
			files, err := s.Store.FilesByLayer(cctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve files for %v: %w", layer.Hash, err)
			}
			la.Files = append(la.Files, files...)
			// pack artifacts array in layer order
			artifacts = append(artifacts, la)
		}
		coalescer, err := ecosystem.Coalescer(cctx)
		if err != nil {
			return Terminal, fmt.Errorf("failed to get coalescer from ecosystem: %v", err)
		}
		// dispatch coalescer
		g.Go(func() error {
			sr, err := coalescer.Coalesce(cctx, artifacts)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, sr)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return Terminal, err
	}
	s.report = MergeSR(s.report, reports)
	for _, r := range s.Resolvers {
		s.report = r.Resolve(ctx, s.report, s.manifest.Layers)
	}
	return IndexManifest, nil
}

// MergeSR merges IndexReports.
//
// source is the IndexReport that the indexer is working on.
// merge is an array IndexReports returned from coalescers
func MergeSR(source *claircore.IndexReport, merge []*claircore.IndexReport) *claircore.IndexReport {
	for _, ir := range merge {
		for k, v := range ir.Environments {
			source.Environments[k] = append(source.Environments[k], v...)
		}
		for k, v := range ir.Packages {
			source.Packages[k] = v
		}

		for k, v := range ir.Distributions {
			source.Distributions[k] = v
		}

		for k, v := range ir.Repositories {
			source.Repositories[k] = v
		}

		for k, v := range ir.Files {
			source.Files[k] = v
		}
	}
	return source
}
