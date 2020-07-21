package rhel

import (
	"context"
	"strconv"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/log"
)

// Test_Coalescer tests the private method coalesce on the rhel.Coalescer.
// it's simpler to test the core business logic of a rhel.Coalescer after
// database access would have occurred. Thus we do not use a black box test
// and instead test private methods.
func Test_Coalescer(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := NewCoalescer()
	// we will test
	// 1) packages before a distribution was discovered are tagged with
	//    the first distribution found
	// 2) all packages found after a subsequent distribution is located
	//    are tagged wih this distribution
	pkgs := test.GenUniquePackages(6)
	dists := test.GenUniqueDistributions(3) // we will discard dist 0 due to zero value ambiguity
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:1],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:2],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:3],
			Dist:  dists[1:2],
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:4],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:5],
			Dist:  dists[2:],
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:],
			Dist:  nil,
			Repos: nil,
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	// we expect packages 1-4 to be tagged with dist id 1
	// and packages 5-6 to be tagged with dist id 2
	for i := 0; i < 4; i++ {
		environment := ir.Environments[strconv.Itoa(i)][0]
		if environment.DistributionID != "1" {
			t.Fatalf("expected distribution id %d but got %s", 1, environment.DistributionID)
		}
	}
	for i := 4; i < 6; i++ {
		environment := ir.Environments[strconv.Itoa(i)][0]
		if environment.DistributionID != "2" {
			t.Fatalf("expected distribution id %d but got %s", 2, environment.DistributionID)
		}
	}
}

func Test_Coalescer_cpe_repos(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := NewCoalescer()
	repo1 := &claircore.Repository{
		ID:   "1",
		Name: "rhel-8-for-x86_64-baseos-rpms",
		Key:  RedHatRepositoryKey,
	}
	repo2 := &claircore.Repository{
		ID:   "2",
		Name: "rhel-8-for-x86_64-appstream-rpms",
		Key:  RedHatRepositoryKey,
	}
	repo3 := &claircore.Repository{
		ID:   "3",
		Name: "rhel-8-for-x86_64-appstream-rpms",
		Key:  RedHatRepositoryKey,
	}

	pkgs := test.GenUniquePackages(5)
	dists := test.GenUniqueDistributions(3) // we will discard dist 0 due to zero value ambiguity
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:1],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:2],
			Dist:  nil,
			Repos: []*claircore.Repository{repo1, repo2},
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:3],
			Dist:  dists[1:2],
			Repos: []*claircore.Repository{repo3},
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:4],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[0:5],
			Dist:  dists[2:],
			Repos: nil,
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	// we expect packages 1-2 to be associated with repos 1 and 2
	for i := 0; i < 2; i++ {
		environment := ir.Environments[strconv.Itoa(i)][0]
		if len(environment.RepositoryIDs) != 2 || environment.RepositoryIDs[0] != "1" || environment.RepositoryIDs[1] != "2" {
			t.Fatalf("expected repository ids [1, 2] but got %s", environment.RepositoryIDs)
		}
	}
	// and packages 3-5 to be associated with repo 3
	for i := 2; i < 5; i++ {
		environment := ir.Environments[strconv.Itoa(i)][0]
		if len(environment.RepositoryIDs) != 1 || environment.RepositoryIDs[0] != "3" {
			t.Fatalf("expected repository ids [3] but got %s", environment.RepositoryIDs)
		}
	}
}

func Test_Coalescer_updated_package(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := NewCoalescer()
	repo1 := &claircore.Repository{
		ID:   "1",
		Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
		Key:  "rhel-cpe-repo",
	}
	repo2 := &claircore.Repository{
		ID:   "2",
		Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
		Key:  "rhel-cpe-repo",
	}
	pkg1 := &claircore.Package{
		ID:        "1",
		Name:      "foo",
		Version:   "1.0-1",
		PackageDB: "/var/lib/rpm",
	}
	pkg2 := &claircore.Package{
		ID:        "2",
		Name:      "foo",
		Version:   "2.0-1",
		PackageDB: "/var/lib/rpm",
	}
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg1},
			Dist:  nil,
			Repos: []*claircore.Repository{repo1},
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  nil,
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg2},
			Dist:  nil,
			Repos: []*claircore.Repository{repo2},
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	if _, ok := ir.Packages[pkg1.ID]; ok {
		t.Fatalf("Package %v was updated to %v, but previous version is still available", pkg1, pkg2)
	}
	if _, ok := ir.Environments[pkg1.ID]; ok {
		t.Fatalf("Package %v was updated to %v, but previous version is still available in environment", pkg1, pkg2)
	}
	if _, ok := ir.Packages[pkg2.ID]; !ok {
		t.Fatalf("Package %v was updated to %v, but new version is not available", pkg1, pkg2)
	}
	if _, ok := ir.Environments[pkg2.ID]; !ok {
		t.Fatalf("Package %v was updated to %v, but new version is still not available in environment", pkg1, pkg2)
	}
}

func Test_Coalescer_downgraded_package(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := NewCoalescer()
	repo1 := &claircore.Repository{
		ID:   "1",
		Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
		Key:  "rhel-cpe-repo",
	}
	repo2 := &claircore.Repository{
		ID:   "2",
		Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
		Key:  "rhel-cpe-repo",
	}
	pkg1 := &claircore.Package{
		ID:        "1",
		Name:      "foo",
		Version:   "1.0-1",
		PackageDB: "/var/lib/rpm",
	}
	pkg2 := &claircore.Package{
		ID:        "2",
		Name:      "foo",
		Version:   "2.0-1",
		PackageDB: "/var/lib/rpm",
	}
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg2},
			Dist:  nil,
			Repos: []*claircore.Repository{repo1},
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  nil,
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg1},
			Dist:  nil,
			Repos: []*claircore.Repository{repo2},
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	if _, ok := ir.Packages[pkg2.ID]; ok {
		t.Fatalf("Package %v was downgraded to %v, but previous version is still available", pkg2, pkg1)
	}
	if _, ok := ir.Environments[pkg2.ID]; ok {
		t.Fatalf("Package %v was downgraded to %v, but previous version is still available in environment", pkg2, pkg1)
	}
	if _, ok := ir.Packages[pkg1.ID]; !ok {
		t.Fatalf("Package %v was downgraded to %v, but new version is not available", pkg2, pkg1)
	}
	if _, ok := ir.Environments[pkg1.ID]; !ok {
		t.Fatalf("Package %v was downgraded to %v, but new version is still not available in environment", pkg2, pkg1)
	}
}

func Test_Coalescer_removed_package(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := NewCoalescer()
	repo1 := &claircore.Repository{
		ID:   "1",
		Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
		Key:  "rhel-cpe-repo",
	}
	repo2 := &claircore.Repository{
		ID:   "2",
		Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
		Key:  "rhel-cpe-repo",
	}
	pkg1 := &claircore.Package{
		ID:        "1",
		Name:      "foo",
		Version:   "1.0-1",
		PackageDB: "/var/lib/rpm",
	}
	pkg2 := &claircore.Package{
		ID:        "2",
		Name:      "bar",
		Version:   "1.0-1",
		PackageDB: "/var/lib/rpm",
	}
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg1},
			Dist:  nil,
			Repos: []*claircore.Repository{repo1},
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  nil,
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  []*claircore.Package{pkg2},
			Dist:  nil,
			Repos: []*claircore.Repository{repo2},
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	if _, ok := ir.Packages[pkg1.ID]; ok {
		t.Fatalf("Package %v was removed, but it is still available", pkg1)
	}
	if _, ok := ir.Environments[pkg1.ID]; ok {
		t.Fatalf("Package %v was removed, but it is still available in environment", pkg1)
	}
}
