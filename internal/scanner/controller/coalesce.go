package controller

import (
	"context"
	"fmt"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"golang.org/x/sync/errgroup"
)

// coalesce calls each ecosystem's coalescer and merges the returned ScanReports
func coalesce(ctx context.Context, s *Controller) (State, error) {
	coalescers := []scanner.Coalescer{}
	for _, ecosystem := range s.Ecosystems {
		c, err := ecosystem.Coalescer(ctx, s.Store)
		if err != nil {
			return Terminal, fmt.Errorf("failed to create coalescer: %v", err)
		}
		coalescers = append(coalescers, c)
	}

	mu := sync.Mutex{}
	reports := []*claircore.ScanReport{}
	g, gctx := errgroup.WithContext(ctx)
	for _, c := range coalescers {
		cc := c
		g.Go(func() error {
			sr, err := cc.Coalesce(gctx, s.manifest.Layers)
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

	return ScanFinished, nil
}

// MergeSR merges ScanReports.
//
// source is the ScanReport that the scanner is working on.
// merge is an array ScanReports returned from coalescers
func MergeSR(source *claircore.ScanReport, merge []*claircore.ScanReport) *claircore.ScanReport {
	for _, sr := range merge {
		for k, v := range sr.Packages {
			source.Packages[k] = v
		}

		for k, v := range sr.Distributions {
			source.Distributions[k] = v
		}

		for k, v := range sr.Repositories {
			source.Repositories[k] = v
		}

		for k, v := range sr.DistributionByPackage {
			source.DistributionByPackage[k] = v
		}

		for k, v := range sr.RepositoryByPackage {
			source.RepositoryByPackage[k] = v
		}

		for k, v := range sr.PackageIntroduced {
			source.PackageIntroduced[k] = v
		}
	}
	return source
}
