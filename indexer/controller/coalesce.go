package controller

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Coalesce calls each ecosystem's Coalescer and merges the returned IndexReports.
func coalesce(ctx context.Context, s *Controller) (State, error) {
	mu := sync.Mutex{}
	reports := []*claircore.IndexReport{}
	g, gctx := errgroup.WithContext(ctx)
	// Dispatch a Coalescer goroutine for each ecosystem.
	for _, ecosystem := range s.Ecosystems {
		select {
		case <-gctx.Done():
			break
		default:
		}
		artifacts := []*indexer.LayerArtifacts{}
		pkgScanners, _ := ecosystem.PackageScanners(gctx)
		distScanners, _ := ecosystem.DistributionScanners(gctx)
		repoScanners, _ := ecosystem.RepositoryScanners(gctx)
		fileScanners := []indexer.FileScanner{}
		if ecosystem.FileScanners != nil {
			fileScanners, _ = ecosystem.FileScanners(gctx)
		}
		// Pack "artifacts" variable.
		for _, layer := range s.manifest.Layers {
			la := &indexer.LayerArtifacts{
				Hash: layer.Hash,
			}
			var vscnrs indexer.VersionedScanners
			vscnrs.PStoVS(pkgScanners)
			// Get packages from layer.
			pkgs, err := s.Store.PackagesByLayer(gctx, layer.Hash, vscnrs)
			if err != nil {
				// On an early return gctx is canceled, and all in-flight
				// Coalescers are canceled as well.
				return Terminal, fmt.Errorf("failed to retrieve packages for %v: %w", layer.Hash, err)
			}
			la.Pkgs = append(la.Pkgs, pkgs...)
			// Get repos that have been created via the package scanners.
			pkgRepos, err := s.Store.RepositoriesByLayer(gctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve repositories for %v: %w", layer.Hash, err)
			}
			la.Repos = append(la.Repos, pkgRepos...)

			// Get distributions from layer.
			vscnrs.DStoVS(distScanners) // Method allocates new "vscnr" underlying array, clearing old contents.
			dists, err := s.Store.DistributionsByLayer(gctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve distributions for %v: %w", layer.Hash, err)
			}
			la.Dist = append(la.Dist, dists...)
			// Get repositories from layer.
			vscnrs.RStoVS(repoScanners)
			repos, err := s.Store.RepositoriesByLayer(gctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve repositories for %v: %w", layer.Hash, err)
			}
			la.Repos = append(la.Repos, repos...)
			// Get files from layer.
			vscnrs.FStoVS(fileScanners)
			files, err := s.Store.FilesByLayer(gctx, layer.Hash, vscnrs)
			if err != nil {
				return Terminal, fmt.Errorf("failed to retrieve files for %v: %w", layer.Hash, err)
			}
			la.Files = append(la.Files, files...)
			// Pack artifacts array in layer order.
			artifacts = append(artifacts, la)
		}
		coalescer, err := ecosystem.Coalescer(gctx)
		if err != nil {
			return Terminal, fmt.Errorf("failed to get coalescer from ecosystem: %v", err)
		}
		// Dispatch.
		g.Go(func() error {
			sr, err := coalescer.Coalesce(gctx, artifacts)
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
// "Source" is the IndexReport that the Indexer is working on.
// "Merge" is a slice of IndexReports returned from Coalescers.
//
// The "SR" suffix is a historical accident.
func MergeSR(source *claircore.IndexReport, merge []*claircore.IndexReport) *claircore.IndexReport {
	for _, ir := range merge {
		for k, v := range ir.Environments {
			source.Environments[k] = append(source.Environments[k], v...)
		}
		maps.Copy(source.Packages, ir.Packages)

		maps.Copy(source.Distributions, ir.Distributions)

		maps.Copy(source.Repositories, ir.Repositories)

		maps.Copy(source.Files, ir.Files)
	}
	return source
}
