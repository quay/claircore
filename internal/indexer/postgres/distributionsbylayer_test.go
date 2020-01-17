package postgres

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Test_DistributionsByLayer_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// name of the test
		name string
		// the layer hash we want to test
		hash string
		// number dists to create
		dists int
		// number scnrs to create
		scnrs int
	}{
		{
			name:  "10 dists, 5 scanners",
			hash:  "test-layer-hash",
			dists: 10,
			scnrs: 5,
		},
		{
			name:  "50 distss, 25 scanners",
			hash:  "test-layer-hash",
			dists: 50,
			scnrs: 25,
		},
		{
			name:  "100 distss, 50 scanners",
			hash:  "test-layer-hash",
			dists: 100,
			scnrs: 50,
		},
		{
			name:  "500 distss, 250 scanners",
			hash:  "test-layer-hash",
			dists: 500,
			scnrs: 250,
		},
		{
			name:  "1000 distss, 500 scanners",
			hash:  "test-layer-hash",
			dists: 1000,
			scnrs: 500,
		},
		{
			name:  "2000 distss, 1000 scanners",
			hash:  "test-layer-hash",
			dists: 2000,
			scnrs: 1000,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			// generate a specific number of distributions
			dists := test.GenUniqueDistributions(table.dists)

			// index them into the database
			err := pgtest.InsertDistributions(db, dists)
			if err != nil {
				t.Fatalf("failed to insert dists: %v", err)
			}

			// create scnr mocks
			vscnrs := test.GenUniqueDistributionScanners(table.scnrs)
			err = pgtest.InsertUniqueScanners(db, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scnrs: %v", err)
			}

			// create scanartifacts
			err = pgtest.InsertDistScanArtifacts(db, table.hash, dists, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scan artifacts for test: %v", err)
			}

			returnedDists, err := store.DistributionsByLayer(ctx, table.hash, vscnrs)

			sort.SliceStable(dists,
				func(i, j int) bool { return dists[i].ID < dists[j].ID })
			sort.SliceStable(returnedDists,
				func(i, j int) bool { return returnedDists[i].ID < returnedDists[j].ID })

			if !cmp.Equal(dists, returnedDists) {
				diff := cmp.Diff(dists, returnedDists)
				t.Fatalf("security databases were not equal: \n%v", diff)
			}
		})
	}
}
