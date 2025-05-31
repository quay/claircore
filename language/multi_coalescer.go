package language

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ indexer.Coalescer = (*multiCoalescer)(nil)

type multiCoalescer struct{}

// NewMultiCoalescer returns a new common programming language coalescer.
//
// This coalescer should be used for languages which may have multiple packages
// in the same filepath (ex: go or java).
func NewMultiCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &multiCoalescer{}, nil
}

// Coalesce implements [indexer.Coalescer].
//
// This is suitable for those languages which may have multiple packages within the same filepath.
//
// TODO(ross): This method runs into the problem which (*coalescer).Coalesce aimed to solve.
// However, if only certain ecosystems use this, then the problem is much less likely to occur.
// A problem occurred when images were built with some Node.js package in one layer
// which is subsequently updated in another layer. This problem is much less likely to happen to
// Go and Java packages, as Go packages are immutable binaries, which are unlikely to be updated between layers,
// and Java packages are JAR files which tend to use different names between versions.
// Nonetheless, it'd be great to have a solution for those ecosystems, too.
func (*multiCoalescer) Coalesce(_ context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}

	for _, l := range ls {
		// If we didn't find at least one repo in this layer no point searching for packages.
		if len(l.Repos) == 0 {
			continue
		}
		rs := make([]string, len(l.Repos))
		for i, r := range l.Repos {
			rs[i] = r.ID
			ir.Repositories[r.ID] = r
		}
		for _, pkg := range l.Pkgs {
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
