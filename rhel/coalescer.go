package rhel

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Coalescer takes individual layer artifacts and coalesces them to form the final image's
// package results
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

// Coalesce coalesces artifacts found in layers and creates a final IndexReport with
// the final package details found in the image. This method blocks and when its finished
// the c.ir field will hold the final IndexReport
func (c *Coalescer) Coalesce(ctx context.Context, artifacts []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Share repositories with layers where definition is missing
	c.shareRepos(ctx, artifacts)
	for _, a := range artifacts {
		for _, repo := range a.Repos {
			c.ir.Repositories[repo.ID] = repo
		}
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
					packages := map[string]*claircore.Package{}
					environments := map[string]*claircore.Environment{}
					dbs[pkg.PackageDB] = &packageDatabase{packages, environments}
				}
				if _, ok := dbs[pkg.PackageDB].packages[pkg.ID]; !ok {
					environment := &claircore.Environment{
						PackageDB:      pkg.PackageDB,
						IntroducedIn:   layerArtifacts.Hash,
						DistributionID: distID,
					}
					for _, repo := range layerArtifacts.Repos {
						environment.RepositoryIDs = append(environment.RepositoryIDs, repo.ID)
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

	// Now let's go through packages and finds out whether each package is still
	// available in package database in higher layers.
	// When package is not available in higher layers it means that package was
	// either updated/downgraded/removed. In such a cases we need to remove it
	// from list of packages
	// If a package is available in all layers it means that it should be added
	// to list of packages and associate an environment for it.
	for i := 0; i < len(artifacts); i++ {
		currentLayerArtifacts := artifacts[i]
		if len(currentLayerArtifacts.Pkgs) == 0 {
			continue
		}
		for _, currentPkg := range currentLayerArtifacts.Pkgs {
			if _, ok := c.ir.Packages[currentPkg.ID]; ok {
				// the package was already processed in previous layers
				continue
			}
			// for each package let's find out if it is also available in other layers dbs
			found := true
			for j := i + 1; j < len(artifacts); j++ {
				nextLayerArtifacts := artifacts[j]
				if len(nextLayerArtifacts.Pkgs) == 0 {
					continue
				}
				found = false
				for _, nextPkg := range nextLayerArtifacts.Pkgs {
					if currentPkg.ID == nextPkg.ID && currentPkg.PackageDB == nextPkg.PackageDB {
						found = true
						break
					}
				}
			}
			if found {
				c.ir.Packages[currentPkg.ID] = currentPkg
				c.ir.Environments[currentPkg.ID] = append(c.ir.Environments[currentPkg.ID], dbs[currentPkg.PackageDB].environments[currentPkg.ID])
			}
		}
	}
	return c.ir, nil
}

// shareRepos takes repository definition and share it with other layers
// where repositories are missing
func (c *Coalescer) shareRepos(ctx context.Context, artifacts []*indexer.LayerArtifacts) {
	// User's layers build on top of Red Hat images doesn't have a repository definition.
	// We need to share CPE repo definition to all layer where CPEs are missing
	// This only applies to Red Hat images
	var previousredHatCpeRepos []*claircore.Repository
	for i := 0; i < len(artifacts); i++ {
		redHatCpeRepos := getRedHatCPERepos(artifacts[i].Repos)
		if len(redHatCpeRepos) != 0 {
			previousredHatCpeRepos = redHatCpeRepos
		} else {
			artifacts[i].Repos = append(artifacts[i].Repos, previousredHatCpeRepos...)
		}
	}
	// Tha same thing has to be done in reverse
	// example:
	//   Red Hat's base images doesn't have repository definition
	//   We need to get them from layer[i+1]
	for i := len(artifacts) - 1; i >= 0; i-- {
		redHatCpeRepos := getRedHatCPERepos(artifacts[i].Repos)
		if len(redHatCpeRepos) != 0 {
			previousredHatCpeRepos = redHatCpeRepos
		} else {
			artifacts[i].Repos = append(artifacts[i].Repos, previousredHatCpeRepos...)
		}
	}

}

// getRedHatCPERepos finds Red Hat's CPE based repositories and return them
func getRedHatCPERepos(repos []*claircore.Repository) []*claircore.Repository {
	redHatCPERepos := []*claircore.Repository{}
	for _, repo := range repos {
		if repo.Key == RedHatRepositoryKey {
			redHatCPERepos = append(redHatCPERepos, repo)
		}
	}
	return redHatCPERepos
}
