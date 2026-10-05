package java

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type coalescer struct{}

func (*coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}

	for _, l := range ls {
		// If we didn't find at least one repository in this layer
		// no point in searching for packages.
		if len(l.Repos) == 0 {
			continue
		}
		var mavenIDs []string
		for _, r := range l.Repos {
			if r.Name == Repository.Name && r.Key == "" {
				mavenIDs = append(mavenIDs, r.ID)
			}
		}
		for _, pkg := range l.Pkgs {
			ir.Packages[pkg.ID] = pkg
			rs := mavenIDs
			if strings.HasPrefix(pkg.PackageDB, "sbom:") {
				rs = sbomRepositoryIDs(ctx, pkg, l.Repos)
			}
			for _, id := range rs {
				if repo := repositoryByID(l.Repos, id); repo != nil {
					ir.Repositories[repo.ID] = repo
				}
			}
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

func sbomRepositoryIDs(ctx context.Context, pkg *claircore.Package, repos []*claircore.Repository) []string {
	q, err := url.ParseQuery(pkg.RepositoryHint)
	if err != nil {
		slog.DebugContext(ctx, "sbom repository hint", "reason", err)
		return nil
	}
	want := q.Get("cpe")
	if want == "" {
		return nil
	}
	for _, r := range repos {
		if r.Key != RedHatCPERepositoryKey {
			continue
		}
		if r.Name == want || r.CPE.String() == want {
			return []string{r.ID}
		}
	}
	slog.DebugContext(ctx, "sbom package has no product repository", "package", pkg.Name, "cpe", want)
	return nil
}

func repositoryByID(repos []*claircore.Repository, id string) *claircore.Repository {
	for _, r := range repos {
		if r.ID == id {
			return r
		}
	}
	return nil
}
