package linux

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/osrelease"
)

// layerArifact aggregates the any artifacts found within a layer
type layerArtifacts struct {
	hash  claircore.Digest
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
	store indexer.Store
	ps    indexer.PackageScanner
	ds    indexer.DistributionScanner
	ir    *claircore.IndexReport
}

// NewCoalescer is a constructor for a Coalescer
func NewCoalescer(store indexer.Store, ps indexer.PackageScanner) *Coalescer {
	return &Coalescer{
		store: store,
		ps:    ps,
		ds:    &osrelease.Scanner{},
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
func (c *Coalescer) Coalesce(ctx context.Context, layers []*claircore.Layer) (*claircore.IndexReport, error) {
	var err error
	// populate layer artifacts
	artifacts := []layerArtifacts{}
	for _, layer := range layers {
		a := layerArtifacts{
			hash: layer.Hash,
		}

		a.pkgs, err = c.store.PackagesByLayer(ctx, layer.Hash, indexer.VersionedScanners{c.ps})
		if err != nil {
			return nil, err
		}

		a.dist, err = c.store.DistributionsByLayer(ctx, layer.Hash, indexer.VersionedScanners{c.ds})
		if err != nil {
			return nil, err
		}

		artifacts = append(artifacts, a)
	}
	err = c.coalesce(ctx, artifacts)
	return c.ir, err
}

// coalesce performs the business logic of coalescing context free scanned artifacts
// into a penultimate IndexReport. this method is heavily commented to express
// the reasoning and assumptions.
func (c *Coalescer) coalesce(ctx context.Context, artifacts []layerArtifacts) error {
	if ctx.Err() != nil {
		return ctx.Err()
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
		if len(a.dist) != 0 {
			currDist = a.dist[0]
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
		if len(layerArtifacts.dist) != 0 {
			currDist = layerArtifacts.dist[0]
			c.ir.Distributions[currDist.ID] = currDist
		}
		// associate packages with their environments
		if len(layerArtifacts.pkgs) != 0 {
			for _, pkg := range layerArtifacts.pkgs {
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
						IntroducedIn:   layerArtifacts.hash,
						DistributionID: distID,
					}
					environments := map[string]*claircore.Environment{pkg.ID: environment}
					dbs[pkg.PackageDB] = &packageDatabase{packages, environments}
					continue
				}
				if _, ok := dbs[pkg.PackageDB].packages[pkg.ID]; !ok {
					environment := &claircore.Environment{
						PackageDB:      pkg.PackageDB,
						IntroducedIn:   layerArtifacts.hash,
						DistributionID: distID,
					}
					dbs[pkg.PackageDB].packages[pkg.ID] = pkg
					dbs[pkg.PackageDB].environments[pkg.ID] = environment
				}
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
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
		if len(layerArtifacts.pkgs) == 0 {
			continue
		}
		// used as a temporary accumulator of package ids in this layer
		var tmpPackagesToKeep = map[string][]string{}
		for _, pkg := range layerArtifacts.pkgs {
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
	return nil
}
