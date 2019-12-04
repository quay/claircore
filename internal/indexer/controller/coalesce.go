package controller

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// coalesce calls each ecosystem's coalescer and merges the returned IndexReports
func coalesce(ctx context.Context, s *Controller) (State, error) {
	coalescers := []indexer.Coalescer{}
	for _, ecosystem := range s.Ecosystems {
		c, err := ecosystem.Coalescer(ctx, s.Store)
		if err != nil {
			return Terminal, fmt.Errorf("failed to create coalescer: %v", err)
		}
		coalescers = append(coalescers, c)
	}

	mu := sync.Mutex{}
	reports := []*claircore.IndexReport{}
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

	return IndexFinished, nil
}

// MergeSR merges IndexReports.
//
// source is the IndexReport that the indexer is working on.
// merge is an array IndexReports returned from coalescers
func MergeSR(source *claircore.IndexReport, merge []*claircore.IndexReport) *claircore.IndexReport {
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
