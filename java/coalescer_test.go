package java

import (
	"context"
	"net/url"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	rheljava "github.com/quay/claircore/rhel/java"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestCoalescerSplitsRepositories(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	w := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1")
	cpeRepo := &claircore.Repository{
		ID:   "1",
		Name: w.String(),
		Key:  rheljava.RepositoryKey,
		CPE:  w,
	}
	maven := Repository
	maven.ID = "2"

	sbom := &claircore.Package{
		ID:        "10",
		Name:      "com.fasterxml.jackson.core:jackson-databind",
		PackageDB: "sbom:app.cdx.json",
		RepositoryHint: url.Values{
			"cpe": {w.String()},
		}.Encode(),
	}
	jarPkg := &claircore.Package{
		ID:        "11",
		Name:      "org.slf4j:slf4j-api",
		PackageDB: "maven:slf4j-api.jar",
	}
	ir, err := (*coalescer)(nil).Coalesce(ctx, []*indexer.LayerArtifacts{{
		Hash:  test.RandomSHA256Digest(t),
		Pkgs:  []*claircore.Package{sbom, jarPkg},
		Repos: []*claircore.Repository{cpeRepo, &maven},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ir.Environments[sbom.ID][0].RepositoryIDs; len(got) != 1 || got[0] != cpeRepo.ID {
		t.Fatalf("sbom repositories: %v", got)
	}
	if got := ir.Environments[jarPkg.ID][0].RepositoryIDs; len(got) != 1 || got[0] != maven.ID {
		t.Fatalf("jar repositories: %v", got)
	}
	if _, ok := ir.Repositories[maven.ID]; !ok {
		t.Fatal("missing maven repository")
	}
	if _, ok := ir.Repositories[cpeRepo.ID]; !ok {
		t.Fatal("missing cpe repository")
	}
}

func TestCoalescerMultipleProductCPEs(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	q := cpe.MustUnbind("cpe:/a:redhat:quarkus:3.33")
	c := cpe.MustUnbind("cpe:/a:redhat:apache_camel_quarkus:3.33")
	quarkus := &claircore.Repository{ID: "1", Name: q.String(), Key: rheljava.RepositoryKey, CPE: q}
	camel := &claircore.Repository{ID: "2", Name: c.String(), Key: rheljava.RepositoryKey, CPE: c}
	maven := Repository
	maven.ID = "3"
	pkg := &claircore.Package{
		ID:        "10",
		Name:      "io.smallrye:smallrye-graphql",
		PackageDB: "sbom:dependency.cdx.json",
		RepositoryHint: url.Values{
			"cpe": {q.String(), c.String()},
		}.Encode(),
	}
	ir, err := (*coalescer)(nil).Coalesce(ctx, []*indexer.LayerArtifacts{{
		Hash:  test.RandomSHA256Digest(t),
		Pkgs:  []*claircore.Package{pkg},
		Repos: []*claircore.Repository{quarkus, camel, &maven},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := ir.Environments[pkg.ID][0].RepositoryIDs
	want := []string{quarkus.ID, camel.ID}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("repositories: got %v", got)
	}
	if _, ok := ir.Repositories[maven.ID]; ok {
		t.Fatal("sbom package recorded Maven Central")
	}
}

func TestCoalescerDropsCoveredJars(t *testing.T) {
	t.Parallel()
	w := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1")
	cpeRepo := &claircore.Repository{
		ID:   "1",
		Name: w.String(),
		Key:  RedHatCPERepositoryKey,
		CPE:  w,
	}
	maven := Repository
	maven.ID = "2"

	sbomPkg := func(id, name, db, filepath, covered, sum string) *claircore.Package {
		return &claircore.Package{
			ID:        id,
			Name:      name,
			PackageDB: db,
			Filepath:  filepath,
			RepositoryHint: url.Values{
				"cpe":    {w.String()},
				"path":   {covered},
				"sha256": {sum},
			}.Encode(),
		}
	}
	jarPkg := func(id, name, db, filepath, sum string) *claircore.Package {
		return &claircore.Package{
			ID:             id,
			Name:           name,
			PackageDB:      db,
			Filepath:       filepath,
			RepositoryHint: url.Values{
				"sha1":   {"0123456789abcdef0123456789abcdef01234567"},
				"sha256": {sum},
			}.Encode(),
		}
	}

	t.Run("path", func(t *testing.T) {
		t.Parallel()
		ctx := test.Logging(t)
		doc := sbomPkg("10", "org.example:covered", "sbom:sbom.cdx.json:lib/covered-1.0.jar", "lib/covered-1.0.jar", "lib/covered-1.0.jar", "aa")
		covered := jarPkg("11", "covered", "file:lib/covered-1.0.jar", "lib/covered-1.0.jar", "bb")
		other := jarPkg("12", "other", "file:lib/other-1.0.jar", "lib/other-1.0.jar", "cc")
		ir := coalesce(t, ctx, []*indexer.LayerArtifacts{{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{doc, covered, other},
			Repos: []*claircore.Repository{cpeRepo, &maven},
		}})
		if _, ok := ir.Packages[covered.ID]; ok {
			t.Fatal("jar named by path was kept")
		}
		if _, ok := ir.Packages[doc.ID]; !ok {
			t.Fatal("sbom package was dropped")
		}
		if _, ok := ir.Packages[other.ID]; !ok {
			t.Fatal("unnamed jar was dropped")
		}
		if got := ir.Environments[doc.ID][0].RepositoryIDs; len(got) != 1 || got[0] != cpeRepo.ID {
			t.Fatalf("sbom repositories: %v", got)
		}
	})

	t.Run("hash", func(t *testing.T) {
		t.Parallel()
		ctx := test.Logging(t)
		doc := sbomPkg("10", "org.example:hashed", "sbom:meta/app.cdx.json:elsewhere/hashed-1.0.jar", "meta/elsewhere/hashed-1.0.jar", "meta/elsewhere/hashed-1.0.jar", "deadbeef")
		hashed := jarPkg("11", "hashed", "maven:lib/hashed-1.0.jar", "lib/hashed-1.0.jar", "deadbeef")
		ir := coalesce(t, ctx, []*indexer.LayerArtifacts{
			{
				Hash:  test.RandomSHA256Digest(t),
				Pkgs:  []*claircore.Package{doc},
				Repos: []*claircore.Repository{cpeRepo},
			},
			{
				Hash:  test.RandomSHA256Digest(t),
				Pkgs:  []*claircore.Package{hashed},
				Repos: []*claircore.Repository{&maven},
			},
		})
		if _, ok := ir.Packages[hashed.ID]; ok {
			t.Fatal("jar named by digest was kept")
		}
		if _, ok := ir.Packages[doc.ID]; !ok {
			t.Fatal("sbom package was dropped")
		}
	})

	t.Run("embedded", func(t *testing.T) {
		t.Parallel()
		ctx := test.Logging(t)
		doc := sbomPkg("10", "org.example:embedded", "sbom:aaa-app-1.0.jar:META-INF/sbom/dependency.cdx.json:lib/sibling-1.0.jar", "aaa-app-1.0.jar", "lib/sibling-1.0.jar", "abc123")
		sibling := jarPkg("11", "sibling", "jar:lib/sibling-1.0.jar", "lib/sibling-1.0.jar", "ffffff")
		byHash := jarPkg("12", "outside", "file:opt/outside-1.0.jar", "opt/outside-1.0.jar", "ABC123")
		ir := coalesce(t, ctx, []*indexer.LayerArtifacts{{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{doc, sibling, byHash},
			Repos: []*claircore.Repository{cpeRepo, &maven},
		}})
		if _, ok := ir.Packages[sibling.ID]; ok {
			t.Fatal("jar named by embedded path was kept")
		}
		if _, ok := ir.Packages[byHash.ID]; ok {
			t.Fatal("jar named by embedded digest was kept")
		}
		if _, ok := ir.Packages[doc.ID]; !ok {
			t.Fatal("embedded sbom package was dropped")
		}
		if got := ir.Environments[doc.ID][0].RepositoryIDs; len(got) != 1 || got[0] != cpeRepo.ID {
			t.Fatalf("sbom repositories: %v", got)
		}
	})
}

func coalesce(t *testing.T, ctx context.Context, ls []*indexer.LayerArtifacts) *claircore.IndexReport {
	t.Helper()
	ir, err := (*coalescer)(nil).Coalesce(ctx, ls)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}
