package language

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ indexer.Coalescer = (*coalescer)(nil)

type coalescer struct{}

func NewCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &coalescer{}, nil
}

func (c *coalescer) Coalesce(_ context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}
	// Similar to ir.Packages, except instead of mapping
	// id -> package, it maps packageDB -> package.
	// For langauge packages, it is possible the
	// packageDB is overwritten.
	packages := make(map[string]*claircore.Package)
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
		// If we didn't find at least one repo in this layer
		// no point in searching for packages.
		if len(l.Repos) == 0 {
			continue
		}
		rs := make([]string, len(l.Repos))
		for i, r := range l.Repos {
			rs[i] = r.ID
			ir.Repositories[r.ID] = r
		}
		for _, pkg := range l.Pkgs {
			if childPkg, exists := packages[pkg.PackageDB]; exists {
				// If the package was renamed or has a different version in a high layer,
				// then we consider this a different package and ignore the
				// original in the lower layer.
				if pkg.Name != childPkg.Name || pkg.Version != childPkg.Version {
					continue
				}
				// The name and version is the same, so delete the entry related to the higher
				// layer, as this package was likely introduced in the lower layer.
				delete(ir.Packages, childPkg.ID)
				delete(ir.Environments, childPkg.ID)
			}
			packages[pkg.PackageDB] = pkg
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
