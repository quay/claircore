// Package language implements structs and functions common between
// programming language indexing implementations.
package language

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ indexer.Coalescer = (*coalescer)(nil)

type coalescer struct{}

// NewCoalescer returns a new common programming language coalescer.
func NewCoalescer(_ context.Context) (indexer.Coalescer, error) {
	return &coalescer{}, nil
}

// Coalesce implements [indexer.Coalescer].
//
// Image builders may opt to update language-packages instead of deleting and recreating them
// (as in, there may or may not be a whiteout file to make it clear the package was updated).
// This function ensures both scenarios are supported.
//
// This should only be used when there is only a single package at a filepath.
// This is unsuitable for languages which have multiple packages at a filepath.
func (c *coalescer) Coalesce(_ context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}
	// Similar to ir.Packages, except instead of mapping
	// id -> package, it maps filepath -> package.
	// For language packages, it is possible the
	// filepath is overwritten between subsequent layers.
	packages := make(map[string]*claircore.Package)
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
		// If we didn't find at least one repo in this layer
		// no point searching for packages.
		if len(l.Repos) == 0 {
			continue
		}
		rs := make([]string, len(l.Repos))
		for i, r := range l.Repos {
			rs[i] = r.ID
			ir.Repositories[r.ID] = r
		}
		for _, pkg := range l.Pkgs {
			if seen, exists := packages[pkg.Filepath]; exists {
				// If the package was renamed or has a different version in a higher (previously seen) layer,
				// then this is considered a different package.
				// In that case, ignore the original package in the lower (this) layer.
				if pkg.Name != seen.Name || pkg.Version != seen.Version {
					continue
				}
				// The name and version are the same, so delete the entry related to the higher (previously seen)
				// layer, as this package was likely introduced in the lower (this) layer.
				delete(ir.Packages, seen.ID)
				delete(ir.Environments, seen.ID)
			}
			packages[pkg.Filepath] = pkg
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
