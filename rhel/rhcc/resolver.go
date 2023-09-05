package rhcc

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	_ indexer.Resolver = (*Resolver)(nil)
)

type Resolver struct{}

func (r *Resolver) Resolve(ctx context.Context, ir *claircore.IndexReport, layers []*claircore.Layer) *claircore.IndexReport {
	rhLayers := []claircore.Digest{}
	// TODO: Should we look at repos here? Nicer to find but harder to use.
	for id, p := range ir.Packages {
		if p.RepositoryHint == "rhcc" {
			// Grab the layers where rhcc packages exist.
			for _, e := range ir.Environments[id] {
				rhLayers = append(rhLayers, e.IntroducedIn)
			}
		}
	}
	problematicPkgIDs := []string{}
	// Check which packages come from those layers.
	for pkgID, es := range ir.Environments {
		for _, e := range es {
			for _, rhl := range rhLayers {
				if e.IntroducedIn.String() == rhl.String() {
					problematicPkgIDs = append(problematicPkgIDs, pkgID)
				}
			}
		}
	}
	finalPackages := map[string]*claircore.Package{}
	finalEnvironments := map[string][]*claircore.Environment{}
	for pkgID, pkg := range ir.Packages {
		packageDelete := false
		for _, ppkgID := range problematicPkgIDs {
			if ppkgID == pkgID && (pkg.RepositoryHint != "rhcc") {
				// TODO: Do we actually want to delete this package or make it unmatchable?
				// TODO: Do we want to delete every other package or just ones from
				// certain ecosystems, if so, how do we identify them?
				// TODO: Do we add rpm packages here?
				packageDelete = true
			}
		}
		if !packageDelete {
			finalPackages[pkgID] = pkg
			finalEnvironments[pkgID] = ir.Environments[pkgID]
		}
	}
	ir.Packages = finalPackages
	ir.Environments = finalEnvironments
	return ir
}
