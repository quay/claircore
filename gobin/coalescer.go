package gobin

import (
	"context"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type coalescer struct{}

func (c *coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}
	for _, l := range ls {
		var rid string
		for _, r := range l.Repos {
			// Magic strings copied out of the osv package.
			if r.Name != `go` || r.URI != `https://pkg.go.dev/` {
				continue
			}
			rid = r.ID
			ir.Repositories[r.ID] = r
			break
		}
		for _, pkg := range l.Pkgs {
			if !strings.HasPrefix(pkg.PackageDB, "go:") {
				continue
			}
			ir.Packages[pkg.ID] = pkg
			ir.Environments[pkg.ID] = []*claircore.Environment{
				{
					PackageDB:     pkg.PackageDB,
					IntroducedIn:  l.Hash,
					RepositoryIDs: []string{rid},
				},
			}
		}
	}
	return ir, nil
}
