package python

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var scanners = []indexer.PackageScanner{&Scanner{}}

// NewEcosystem provides the set of scanners for the python ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners:      func(_ context.Context) ([]indexer.PackageScanner, error) { return scanners, nil },
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners:   func(_ context.Context) ([]indexer.RepositoryScanner, error) { return nil, nil },
		Coalescer:            NewCoalescer,
	}
}

func NewCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &coalescer{}, nil
}

type coalescer struct {
}

func (c *coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	repos := make(map[string]string)
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}
	var repoIdx int
	for _, l := range ls {
		for _, pkg := range l.Pkgs {
			ir.Packages[pkg.ID] = pkg
			// Look for the repository to be one we've already used, then look
			// in the layer, then make one up.
			repoid, ok := repos[pkg.RepositoryHint]
			if !ok {
				repoid = fmt.Sprintf("python:%04d", repoIdx)
				repoIdx++
				set := false
				for _, r := range l.Repos {
					if r.URI == pkg.RepositoryHint {
						ir.Repositories[repoid] = r
						set = true
						break
					}
				}
				if !set {
					ir.Repositories[repoid] = &claircore.Repository{
						URI: pkg.RepositoryHint,
					}
				}
				repos[pkg.RepositoryHint] = repoid
			}

			ir.Environments[pkg.ID] = []*claircore.Environment{
				&claircore.Environment{
					PackageDB:     pkg.PackageDB,
					IntroducedIn:  l.Hash,
					RepositoryIDs: []string{repoid},
				},
			}
		}
	}
	return ir, nil
}
