package linux

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type Coalescer struct {
	// the IndexReport this Coalescer is working on
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

// Coalesce coalesces artifacts found in layers and creates an IndexReport with
// the final package details found in the image. This method blocks and when its finished
// the c.ir field will hold the final IndexReport
func (c *Coalescer) Coalesce(ctx context.Context, layerArtifacts []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	distSearcher := NewDistSearcher(layerArtifacts)
	packageSearcher := NewPackageSearcher(layerArtifacts)

	// get all dists the seacher knows about
	dists := distSearcher.Dists()
	for _, dist := range dists {
		c.ir.Distributions[dist.ID] = dist
	}

	// walk layers backwards, grouping packages by package databases the first time we see them.
	// at the end of this loop we have searched all layers for the newest occurence of a
	// package database.
	dbs := make(map[string][]*claircore.Package)
	for i := len(layerArtifacts) - 1; i >= 0; i-- {
		artifacts := layerArtifacts[i]
		if len(artifacts.Pkgs) == 0 {
			continue
		}

		tmp := make(map[string][]*claircore.Package)
		for _, pkg := range artifacts.Pkgs {
			if _, ok := dbs[pkg.PackageDB]; !ok {
				tmp[pkg.PackageDB] = append(tmp[pkg.PackageDB], pkg)
			}
		}
		for db, pkgs := range tmp {
			dbs[db] = pkgs
		}
	}

	for db, packages := range dbs {
		for _, pkg := range packages {
			// create our environment
			env := &claircore.Environment{}

			// get the digest and index of the layer this pkg was introduced in.
			introDigest, introIndex, err := packageSearcher.Search(pkg)
			if err != nil {
				return nil, fmt.Errorf("search for package introduction info failed: %v", err)
			}

			// get the distribution associated with ths layer index
			dist, err := distSearcher.Search(introIndex)
			if err != nil {
				return nil, fmt.Errorf("search for distribution to tag package failed: %v", err)
			}

			// pack env
			if dist != nil {
				env.DistributionID = dist.ID
			}
			env.IntroducedIn = *introDigest
			env.PackageDB = db

			// pack ir
			c.ir.Packages[pkg.ID] = pkg
			c.ir.Environments[pkg.ID] = append(c.ir.Environments[pkg.ID], env)
		}
	}

	return c.ir, nil
}
