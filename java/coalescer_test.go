package java

import (
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
