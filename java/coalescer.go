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

	claims := newSbomClaims(ctx, ls)

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
			if claims.covers(pkg) {
				slog.DebugContext(ctx, "skipping jar covered by sbom", "package", pkg.Name, "path", pkg.Filepath)
				continue
			}
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

// sbomClaims is the set of JARs named by SBOM packages across every layer.
// An SBOM in one layer can name a JAR in another, and an SBOM inside a JAR
// can name a JAR outside that archive. Both claims are on the hint.
type sbomClaims struct {
	path   map[string]struct{}
	sha1   map[string]struct{}
	sha256 map[string]struct{}
}

func newSbomClaims(ctx context.Context, ls []*indexer.LayerArtifacts) sbomClaims {
	c := sbomClaims{
		path:   map[string]struct{}{},
		sha1:   map[string]struct{}{},
		sha256: map[string]struct{}{},
	}
	for _, l := range ls {
		for _, pkg := range l.Pkgs {
			if !strings.HasPrefix(pkg.PackageDB, "sbom:") {
				continue
			}
			q, err := url.ParseQuery(pkg.RepositoryHint)
			if err != nil {
				slog.DebugContext(ctx, "sbom repository hint", "reason", err)
				continue
			}
			if p := q.Get("path"); p != "" {
				c.path[p] = struct{}{}
			}
			for _, sum := range q["sha1"] {
				c.sha1[strings.ToLower(sum)] = struct{}{}
			}
			for _, sum := range q["sha256"] {
				c.sha256[strings.ToLower(sum)] = struct{}{}
			}
		}
	}
	return c
}

// covers reports whether pkg is a JAR scan that an SBOM already named, either
// by layer path or by digest.
func (c sbomClaims) covers(pkg *claircore.Package) bool {
	switch {
	case strings.HasPrefix(pkg.PackageDB, "file:"),
		strings.HasPrefix(pkg.PackageDB, "jar:"),
		strings.HasPrefix(pkg.PackageDB, "maven:"):
	default:
		return false
	}
	if _, ok := c.path[pkg.Filepath]; ok {
		return true
	}
	q, err := url.ParseQuery(pkg.RepositoryHint)
	if err != nil {
		return false
	}
	if sum := strings.ToLower(q.Get("sha1")); sum != "" {
		if _, ok := c.sha1[sum]; ok {
			return true
		}
	}
	if sum := strings.ToLower(q.Get("sha256")); sum != "" {
		if _, ok := c.sha256[sum]; ok {
			return true
		}
	}
	return false
}

func sbomRepositoryIDs(ctx context.Context, pkg *claircore.Package, repos []*claircore.Repository) []string {
	q, err := url.ParseQuery(pkg.RepositoryHint)
	if err != nil {
		slog.DebugContext(ctx, "sbom repository hint", "reason", err)
		return nil
	}
	wants := q["cpe"]
	if len(wants) == 0 {
		return nil
	}
	var ids []string
	seen := make(map[string]struct{}, len(wants))
	for _, want := range wants {
		var matched bool
		for _, r := range repos {
			if r.Key != RedHatCPERepositoryKey {
				continue
			}
			if r.Name != want && r.CPE.String() != want {
				continue
			}
			matched = true
			if _, ok := seen[r.ID]; ok {
				continue
			}
			seen[r.ID] = struct{}{}
			ids = append(ids, r.ID)
		}
		if !matched {
			slog.DebugContext(ctx, "sbom package has no product repository", "package", pkg.Name, "cpe", want)
		}
	}
	return ids
}

func repositoryByID(repos []*claircore.Repository, id string) *claircore.Repository {
	for _, r := range repos {
		if r.ID == id {
			return r
		}
	}
	return nil
}
