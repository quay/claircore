package linux

import (
	"context"
	"strconv"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/log"
)

func Test_Coalescer(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	coalescer := &Coalescer{
		ir: &claircore.IndexReport{
			Environments:  map[string][]*claircore.Environment{},
			Packages:      map[string]*claircore.Package{},
			Distributions: map[string]*claircore.Distribution{},
			Repositories:  map[string]*claircore.Repository{},
		},
	}
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
			Pkgs:  pkgs[1:2],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[2:3],
			Dist:  dists[1:2],
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[3:4],
			Dist:  nil,
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[4:5],
			Dist:  dists[2:],
			Repos: nil,
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[5:],
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
