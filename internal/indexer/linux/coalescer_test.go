package linux

import (
	"context"
	"strconv"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/log"
)

// Test_Coalescer tests the private method coalesce on the linux.Coalescer.
// it's simpler to test the core business logic of a linux.Coalescer after
// database access would have occured. Thus we do not use a black box test
// and instead test private methods.
func Test_Coalescer(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	coalescer := &Coalescer{
		store: nil,
		ps:    nil,
		ds:    nil,
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
	layerArtifacts := []layerArtifacts{
		{
			hash:  "A",
			pkgs:  pkgs[0:1],
			dist:  nil,
			repos: nil,
		},
		{
			hash:  "B",
			pkgs:  pkgs[1:2],
			dist:  nil,
			repos: nil,
		},
		{
			hash:  "C",
			pkgs:  pkgs[2:3],
			dist:  dists[1:2],
			repos: nil,
		},
		{
			hash:  "D",
			pkgs:  pkgs[3:4],
			dist:  nil,
			repos: nil,
		},
		{
			hash:  "E",
			pkgs:  pkgs[4:5],
			dist:  dists[2:],
			repos: nil,
		},
		{
			hash:  "F",
			pkgs:  pkgs[5:],
			dist:  nil,
			repos: nil,
		},
	}
	err := coalescer.coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	// we expect packages 1-4 to be tagged with dist id 1
	// and packages 5-6 to be tagged with dist id 2
	for i := 0; i < 4; i++ {
		environment := coalescer.ir.Environments[strconv.Itoa(i)][0]
		if environment.DistributionID != "1" {
			t.Fatalf("expected distribution id %d but got %s", 1, environment.DistributionID)
		}
	}
	for i := 4; i < 6; i++ {
		environment := coalescer.ir.Environments[strconv.Itoa(i)][0]
		if environment.DistributionID != "2" {
			t.Fatalf("expected distribution id %d but got %s", 2, environment.DistributionID)
		}
	}
}
