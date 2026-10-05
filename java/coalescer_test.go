package java

import (
	"net/url"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
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
		Key:  RedHatCPERepositoryKey,
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
