package language

import (
	"context"
	"slices"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ indexer.Coalescer = (*coalescer)(nil)

type coalescer struct{}

func NewCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &coalescer{}, nil
}

type pkgKey struct {
	packageDB string
	name      string
}

func (c *coalescer) Coalesce(_ context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}
	packages := make(map[pkgKey]*claircore.Package)
	// Iterate layers bottom-up so that the topmost (latest) layer wins for duplicate packages.
	for _, l := range slices.Backward(ls) {
		// If we didn't find at least one repo in this layer,
		// there's no point in searching for packages.
		if len(l.Repos) == 0 {
			continue
		}
		rs := make([]string, len(l.Repos))
		for i, r := range l.Repos {
			rs[i] = r.ID
			ir.Repositories[r.ID] = r
		}
		for _, pkg := range l.Pkgs {
			key := pkgKey{packageDB: pkg.PackageDB, name: pkg.Name}
			// Delete the previously seen package in favor of the latest.
			// If the version is different, they should be considered different packages.
			if seen, exists := packages[key]; exists {
				if pkg.Version != seen.Version {
					continue
				}
				delete(ir.Packages, seen.ID)
				delete(ir.Environments, seen.ID)
			}
			packages[key] = pkg
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
