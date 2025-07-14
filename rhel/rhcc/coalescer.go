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

	// We need to find the last layer that has rhcc content.
	lastRHCCLayer := true
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
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
			if !lastRHCCLayer {
				// Discount the package for matching by setting its
				// NormalizedVersion.Kind to UnmatchableKind.
				pkg.NormalizedVersion.Kind = claircore.UnmatchableKind
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
		lastRHCCLayer = false
	}
	return ir, nil
}
