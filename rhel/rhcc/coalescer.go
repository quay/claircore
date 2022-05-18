package rhcc

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// coalescer takes individual layer artifacts and coalesces them to form the final image's
// package results
type coalescer struct{}

func (c *coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}

	for _, l := range ls {
		if len(l.Repos) == 0 {
			continue
		}
		rs := make([]string, len(l.Repos))
		for i, r := range l.Repos {
			rs[i] = r.ID
			ir.Repositories[r.ID] = r
		}
		for _, pkg := range l.Pkgs {
			if pkg.RepositoryHint != `rhcc` {
				continue
			}
			ir.Packages[pkg.ID] = pkg
			ir.Environments[pkg.ID] = []*claircore.Environment{
				{
					PackageDB:     pkg.PackageDB,
					IntroducedIn:  l.Hash,
					RepositoryIDs: rs,
				},
			}
		}
	}
	return ir, nil
}
