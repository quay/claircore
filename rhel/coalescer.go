package rhel

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Coalescer takes individual layer artifacts and coalesces them into a full
// report on the manifest's contents.
//
// Due to the specifics of the RHEL build system, some information needs to be
// back-propagated. That is to say, some information discovered in later layers
// is also attributed to earlier layers. Both the product and distribution
// information work this way.
//
// A Coalescer is safe for concurrent use.
type Coalescer struct{}

var _ indexer.Coalescer = (*Coalescer)(nil)

// Coalesce implements [indexer.Coalescer].
func (*Coalescer) Coalesce(ctx context.Context, artifacts []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	// The comments in here have been largely audited to have consistent language, but
	// "CPE," "repository," and "product" may be used interchangeably here.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ir := claircore.IndexReport{
		Environments:  map[string][]*claircore.Environment{},
		Packages:      map[string]*claircore.Package{},
		Distributions: map[string]*claircore.Distribution{},
		Repositories:  map[string]*claircore.Repository{},
	}

	// User layers built on top of Red Hat images don't have product CPEs associated with them.
	// We need to share the product information forward to all layers where it's missing.
	// This only applies to Red Hat images, obviously.
	var prev []*claircore.Repository
	for i := range artifacts {
		lr := filterRedHatRepos(artifacts[i].Repos)
		if len(lr) != 0 {
			prev = lr
			continue
		}
		artifacts[i].Repos = append(artifacts[i].Repos, prev...)
	}
	// The same thing has to be done in reverse, because the first layer(s) are missing
	// the relevant information.
	//
	// With [ENGCMP-5332], this shouldn't be needed, so check back in 5 years.
	//
	// [ENGCMP-5332]: https://issues.redhat.com/browse/ENGCMP-5332
	for i := len(artifacts) - 1; i >= 0; i-- {
		lr := filterRedHatRepos(artifacts[i].Repos)
		if len(lr) != 0 {
			prev = lr
			continue
		}
		artifacts[i].Repos = append(artifacts[i].Repos, prev...)
	}
	// This dance with copying the product information in both directions means
	// that if Red Hat product information is found, it "taints" all the layers.
	for _, a := range artifacts {
		for _, repo := range a.Repos {
			ir.Repositories[repo.ID] = repo
		}
	}
	// In our coalescing logic if a Distribution is found in layer "n" all packages found
	// in layers 0..n will be associated with this layer. This is for the same reasons
	// for the repository tainting, above.
	//
	// This may not be needed because of matcher changes.
	var curDist *claircore.Distribution
	for _, a := range artifacts {
		if len(a.Dist) != 0 {
			curDist = a.Dist[0]
			ir.Distributions[curDist.ID] = curDist
			break
		}
	}
	// Next, let's begin associating packages with their Environment. We must
	// consider each package in a package database as a unique entity for the
	// edge case where a unique package is located in more then one package
	// database. We'll use a struct as a helper and a map to lookup these
	// structs.
	type packageDatabase struct {
		packages     map[string]*claircore.Package
		environments map[string]*claircore.Environment
	}
	dbs := map[string]*packageDatabase{}

	// Let's walk each layer forward looking for packages, new distributions,
	// and creating the environments we discover packages in.
	for _, layerArtifacts := range artifacts {
		// check if we need to update our currDist
		if len(layerArtifacts.Dist) != 0 {
			curDist = layerArtifacts.Dist[0]
			ir.Distributions[curDist.ID] = curDist
		}
		// associate packages with their environments
		for _, pkg := range layerArtifacts.Pkgs {
			// if we encounter a package where we haven't recorded a package database,
			// initialize the package database
			var distID string
			if curDist != nil {
				distID = curDist.ID
			}
			db, ok := dbs[pkg.PackageDB]
			if !ok {
				db = &packageDatabase{
					packages:     make(map[string]*claircore.Package),
					environments: make(map[string]*claircore.Environment),
				}
				dbs[pkg.PackageDB] = db
			}
			if _, ok := db.packages[pkg.ID]; !ok {
				environment := &claircore.Environment{
					PackageDB:      pkg.PackageDB,
					IntroducedIn:   layerArtifacts.Hash,
					DistributionID: distID,
				}
				pkgRepoHint, _ := url.ParseQuery(pkg.RepositoryHint)
				if pkgRepoid := pkgRepoHint.Get("repoid"); pkgRepoid != "" {
					for _, repo := range layerArtifacts.Repos {
						uri, err := url.ParseQuery(repo.URI)
						if err != nil {
							slog.WarnContext(ctx, "unable to parse repository URI", "repository", repo.URI)
							continue
						}
						repoRepoid := uri.Get("repoid")
						if repoRepoid == pkgRepoid {
							environment.RepositoryIDs = append(environment.RepositoryIDs, repo.ID)
						}
					}
				} else {
					// No repoid was found based on the repositoryHint so associate it
					// to all repositories in the layer.
					environment.RepositoryIDs = make([]string, len(layerArtifacts.Repos))
					for i := range layerArtifacts.Repos {
						environment.RepositoryIDs[i] = layerArtifacts.Repos[i].ID
					}
				}
				db.packages[pkg.ID] = pkg
				db.environments[pkg.ID] = environment
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Now let's go through packages and finds out whether each package is still
	// available in package database in higher layers.
	// When package is not available in higher layers it means that package was
	// either updated/downgraded/removed.
	// If a package is available in all layers it means that it should be added
	// to the list of packages and associate an environment for it.
	for i, currentLayerArtifacts := range artifacts {
		if len(currentLayerArtifacts.Pkgs) == 0 {
			continue
		}
		for _, currentPkg := range currentLayerArtifacts.Pkgs {
			if _, ok := ir.Packages[currentPkg.ID]; ok {
				// The package was already processed in previous layers.
				continue
			}
			// For each package, let's find out if it is also available in other
			// layer's dbs.
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
				ir.Packages[currentPkg.ID] = currentPkg
				ir.Environments[currentPkg.ID] = append(ir.Environments[currentPkg.ID], dbs[currentPkg.PackageDB].environments[currentPkg.ID])
			}
		}
	}
	return &ir, nil
}

// FilterRedHatRepos finds and reports Red Hat's CPE based repositories.
func filterRedHatRepos(in []*claircore.Repository) []*claircore.Repository {
	out := make([]*claircore.Repository, 0, len(in))
	for _, r := range in {
		if r.Key == repositoryKey {
			out = append(out, r)
		}
	}
	return out
}
