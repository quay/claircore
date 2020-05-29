package python

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func NewCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &coalescer{}, nil
}

type coalescer struct {
}

func (c *coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}

	for _, l := range ls {
		// if we didnt' find at least one pip repo in this layer
		// no point in searching for packages
		if len(l.Repos) == 0 {
			continue
		}
		// we found at least one pip repo lets grab it.
		repo := l.Repos[0]

		for _, pkg := range l.Pkgs {
			ir.Packages[pkg.ID] = pkg
			ir.Repositories[repo.ID] = repo
			ir.Environments[pkg.ID] = []*claircore.Environment{
				&claircore.Environment{
					PackageDB:    pkg.PackageDB,
					IntroducedIn: l.Hash,
					RepositoryID: repo.ID,
				},
			}
		}
	}
	return ir, nil
}
