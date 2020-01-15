package linux

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// layerArifact aggregates the any artifacts found within a layer
type layerArtifacts struct {
	hash  string
	pkgs  []*claircore.Package
	dist  []*claircore.Distribution // each layer can only have a single distribution
	repos []*claircore.Repository
}

// Coalescer takes individual layer artifacts and coalesces them to form the final image's
// package results
//
// It is expected to run a coalescer per "ecosystem". For example it would make sense to coalesce results
// for dpkg, os-release, and apt scanners
type Coalescer struct {
	// a store to access scanartifacts
	ir *claircore.IndexReport
}

// NewCoalescer is a constructor for a Coalescer
func NewCoalescer() *Coalescer {
	return &Coalescer{
		ir: &claircore.IndexReport{
			// we will only fill these fields
			Environments:  map[string][]*claircore.Environment{},
			Packages:      map[string]*claircore.Package{},
			Distributions: map[string]*claircore.Distribution{},
			Repositories:  map[string]*claircore.Repository{},
		},
	}
}

// Coalesce coalesces artifacts found in layers and creates a final IndexReport with
// the final package details found in the image. This method blocks and when its finished
// the c.ir field will hold the final IndexReport
func (c *Coalescer) Coalesce(ctx context.Context, artifacts []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// In our coalescing logic if a Distribution is found in layer (n) all packages found
	// in layers 0-(n) will be associated with this layer. This is a heuristic.
	// Let's do a search for the first Distribution we find and use a variable
	// to keep reference of the current Distribution in scope
	// As further Distributions are found we will inventory them and update our currDist pointer,
	// thus tagging all subsequetly found packages with this Distribution.
	// This is a requirement for handling dist upgrades where a layer may have it's operating system updated
	var currDist *claircore.Distribution
	for _, a := range artifacts {
		if len(a.Dist) != 0 {
			currDist = a.Dist[0]
			c.ir.Distributions[currDist.ID] = currDist
			break
		}
	}
	// Next lets begin associating packages with their Environment. We must
	// consider each package in a package database as a unique entity for
	// the edge case where a unique package is located in more then one package database.
	// we'll use a struct as a helper and a map to lookup these structs
	type packageDatabase struct {
		packages     map[string]*claircore.Package
		environments map[string]*claircore.Environment
	}
	var dbs = map[string]*packageDatabase{}
	// lets walk each layer forward looking for packages, new distributions, and
	// creating the environments we discover packages in.
	for _, layerArtifacts := range artifacts {
		// check if we need to update our currDist
		if len(layerArtifacts.Dist) != 0 {
			currDist = layerArtifacts.Dist[0]
			c.ir.Distributions[currDist.ID] = currDist
		}
		// associate packages with their environments
		if len(layerArtifacts.Pkgs) != 0 {
			for _, pkg := range layerArtifacts.Pkgs {
				// if we encounter a package where we haven't recorded a package database,
				// initialize the package database
				var distID string
				if currDist != nil {
					distID = currDist.ID
				}
				if _, ok := dbs[pkg.PackageDB]; !ok {
					packages := map[string]*claircore.Package{pkg.ID: pkg}
					environment := &claircore.Environment{
						PackageDB:      pkg.PackageDB,
						IntroducedIn:   layerArtifacts.Hash,
						DistributionID: distID,
					}
					environments := map[string]*claircore.Environment{pkg.ID: environment}
					dbs[pkg.PackageDB] = &packageDatabase{packages, environments}
					continue
				}
				if _, ok := dbs[pkg.PackageDB].packages[pkg.ID]; !ok {
					environment := &claircore.Environment{
						PackageDB:      pkg.PackageDB,
						IntroducedIn:   layerArtifacts.Hash,
						DistributionID: distID,
					}
					dbs[pkg.PackageDB].packages[pkg.ID] = pkg
					dbs[pkg.PackageDB].environments[pkg.ID] = environment
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// we now have all the packages associated with their introduced in layers and environments.
	// we must now prune any packages removed between layers. this coalescer works on the assumption
	// that any changes to a package's database (dpkg, rpm, alpine, etc...) causes the entire database
	// file to be written to the layer in which the change occurs. this assumption therefore
	// allows for the following algorithm
	// 1) walk layers backwards searching for newest modification of package dabatase.
	// 2) if we encounter a package existing in a particular database it means all packages within this package database are present.
	//    record all packages found into a temporary map.
	//    when we are finished searching the current layer add a key/value to the penultimate map indicating
	//    we no longer care about this set of package databases.
	// 3) continue for all layers, always checking to see if we've already encountered a package database.
	//    as we only want to inventory packages from the newest package database
	// 4) once all layers are scanned begin removing package ids not present in our penultimate packagesToKeep map
	var packagesToKeep = map[string][]string{}
	for i := len(artifacts) - 1; i >= 0; i-- {
		layerArtifacts := artifacts[i]
		if len(layerArtifacts.Pkgs) == 0 {
			continue
		}
		// used as a temporary accumulator of package ids in this layer
		var tmpPackagesToKeep = map[string][]string{}
		for _, pkg := range layerArtifacts.Pkgs {
			// have we already inventoried packages from this database ?
			if _, ok := packagesToKeep[pkg.PackageDB]; !ok {
				// ... we haven't so add to our temporary accumlator
				tk := tmpPackagesToKeep[pkg.PackageDB]
				tmpPackagesToKeep[pkg.PackageDB] = append(tk, pkg.ID)
			}
		}
		for k, v := range tmpPackagesToKeep {
			// finished inventorying the layer, add our inventoried packges to our
			// penultimate map ensuring next iteration will ignore packages from these databases
			packagesToKeep[k] = v
		}
	}
	// now let's prune any packages not found in the newest version of the package databases
	// we just inventoried
	for name, db := range dbs {
		for _, pkg := range db.packages {
			if _, ok := packagesToKeep[name]; !ok {
				delete(db.packages, pkg.ID)
				delete(db.environments, pkg.ID)
			}
		}
	}
	// finally lets pack our results into an IndexReport
	for _, db := range dbs {
		for _, pkg := range db.packages {
			c.ir.Packages[pkg.ID] = pkg
			if _, ok := c.ir.Environments[pkg.ID]; !ok {
				c.ir.Environments[pkg.ID] = []*claircore.Environment{db.environments[pkg.ID]}
				continue
			}
			c.ir.Environments[pkg.ID] = append(c.ir.Environments[pkg.ID], db.environments[pkg.ID])
		}
	}
	return c.ir, nil
}
