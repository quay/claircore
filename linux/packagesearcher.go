package linux

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// PackageSearcher tracks the layer's hash and index a package
// was introduced in.
type PackageSearcher struct {
	m map[string]entry
}

// an entry mapped to a package's key.
// tracks package hash and index pkg was introduced in.
type entry struct {
	digest *claircore.Digest
	index  int
}

// creates a unique key in the package searcher's map
func keyify(pkg *claircore.Package) string {
	return pkg.Name + pkg.PackageDB + pkg.Version
}

// NewPackageSearcher contructs a PackageSearcher ready for its Search method
// to be called
func NewPackageSearcher(layerArtifacts []*indexer.LayerArtifacts) PackageSearcher {
	m := make(map[string]entry, 0)
	for i, artifacts := range layerArtifacts {
		if len(artifacts.Pkgs) == 0 {
			continue
		}

		for _, pkg := range artifacts.Pkgs {
			key := keyify(pkg)
			if _, ok := m[key]; !ok {
				m[key] = entry{
					&artifacts.Hash,
					i,
				}
			}
		}

	}
	return PackageSearcher{m}
}

// Search returns the layer hash and index a package was introduced in.
func (pi *PackageSearcher) Search(pkg *claircore.Package) (*claircore.Digest, int, error) {
	key := keyify(pkg)
	entry, ok := pi.m[key]
	if !ok {
		return nil, 0, nil
	}

	return entry.digest, entry.index, nil
}
