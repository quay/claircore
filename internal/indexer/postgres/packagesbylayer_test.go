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

func Test_PackagesByLayer_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// name of the test
		name string
		// the layer hash we want to test
		hash string
		// number packages to create
		pkgs int
		// number scnrs to create
		scnrs int
	}{
		{
			name:  "10 package, 5 scanners",
			hash:  "test-layer-hash",
			pkgs:  10,
			scnrs: 5,
		},
		{
			name:  "50 packages, 25 scanners",
			hash:  "test-layer-hash",
			pkgs:  50,
			scnrs: 25,
		},
		{
			name:  "100 packages, 50 scanners",
			hash:  "test-layer-hash",
			pkgs:  100,
			scnrs: 50,
		},
		{
			name:  "500 packages, 250 scanners",
			hash:  "test-layer-hash",
			pkgs:  500,
			scnrs: 250,
		},
		{
			name:  "1000 packages, 500 scanners",
			hash:  "test-layer-hash",
			pkgs:  1000,
			scnrs: 500,
		},
		{
			name:  "2000 packages, 1000 scanners",
			hash:  "test-layer-hash",
			pkgs:  2000,
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

			// generate a specific number of packages
			pkgs := test.GenUniquePackages(table.pkgs)

			// index them into the database
			err := pgtest.InsertPackages(db, pkgs)
			if err != nil {
				t.Fatalf("failed to insert packages: %v", err)
			}

			// create scnr mocks
			vscnrs := test.GenUniquePackageScanners(table.scnrs)
			err = pgtest.InsertUniqueScanners(db, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scnrs: %v", err)
			}

			// create scanartifacts
			err = pgtest.InsertPackageScanArtifacts(db, table.hash, pkgs, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scan artifacts for test: %v", err)
			}

			returnedPkgs, err := store.PackagesByLayer(ctx, table.hash, vscnrs)

			sort.SliceStable(pkgs,
				func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })
			sort.SliceStable(returnedPkgs,
				func(i, j int) bool { return returnedPkgs[i].ID < returnedPkgs[j].ID })

			if !cmp.Equal(pkgs, returnedPkgs) {
				diff := cmp.Diff(pkgs, returnedPkgs)
				t.Fatalf("security databases were not equal: \n%v", diff)
			}
		})
	}
}
