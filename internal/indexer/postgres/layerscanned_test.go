package postgres

import (
	"context"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Test_LayerScanned_Packages_False(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of packages to be associated with the scanartifacts and layer hash
		pkgs int
	}{
		{
			name:  "single scanner, single package",
			hash:  "test-layer-hash",
			scnrs: 1,
			pkgs:  1,
		},
		{
			name:  "4 scanners, 4 packages",
			hash:  "test-layer-hash",
			scnrs: 4,
			pkgs:  4,
		},
		{
			name:  "4 scanners, 8 packages",
			hash:  "test-layer-hash",
			scnrs: 4,
			pkgs:  8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniquePackageScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			pkgs := test.GenUniquePackages(table.pkgs)
			err = pgtest.InsertPackages(db, pkgs)

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)
				if err != nil {
					t.Error(err)
				}
				if b {
					t.Fatal("expected false")
				}
			}
		})
	}
}

func Test_LayerScanned_Distributions_False(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of distributions to be associated with the scanartifacts and layer hash
		dists int
	}{
		{
			name:  "single scanner, single distribution",
			hash:  "test-layer-hash",
			scnrs: 1,
			dists: 1,
		},
		{
			name:  "4 scanners, 4 distributions",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 4,
		},
		{
			name:  "4 scanners, 8 distributions",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniqueDistributionScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			dists := test.GenUniqueDistributions(table.dists)
			err = pgtest.InsertDistributions(db, dists)

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)

				if err != nil {
					t.Fatalf("received error checking if layer was scanned: %v", err)
				}
				if b {
					t.Fatalf("expected LayerScanned to return false")
				}
			}
		})
	}
}

func Test_LayerScanned_Repository_False(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of repositories to be associated with the scanartifacts and layer hash
		repos int
	}{
		{
			name:  "single scanner, single repositories",
			hash:  "test-layer-hash",
			scnrs: 1,
			repos: 1,
		},
		{
			name:  "4 scanners, 4 repositories",
			hash:  "test-layer-hash",
			scnrs: 4,
			repos: 4,
		},
		{
			name:  "4 scanners, 8 repositories",
			hash:  "test-layer-hash",
			scnrs: 4,
			repos: 8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniqueRepositoryScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			repos := test.GenUniqueRepositories(table.repos)
			err = pgtest.InsertRepositories(db, repos)

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)
				if err != nil {
					t.Fatalf("received error checking if layer was scanned: %v", err)
				}
				if b {
					t.Fatalf("expected LayerScanned to return false")
				}
			}
		})
	}
}

func Test_LayerScanned_Packages_True(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of packages to be associated with the scanartifacts and layer hash
		pkgs int
	}{
		{
			name:  "single scanner, single package",
			hash:  "test-layer-hash",
			scnrs: 1,
			pkgs:  1,
		},
		{
			name:  "4 scanners, 4 packages",
			hash:  "test-layer-hash",
			scnrs: 4,
			pkgs:  4,
		},
		{
			name:  "4 scanners, 8 packages",
			hash:  "test-layer-hash",
			scnrs: 4,
			pkgs:  8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniquePackageScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			pkgs := test.GenUniquePackages(table.pkgs)
			err = pgtest.InsertPackages(db, pkgs)

			err = pgtest.InsertPackageScanArtifacts(db, table.hash, pkgs, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)
				if err != nil {
					t.Fatalf("received error checking if layer was scanned: %v", err)
				}
				if !b {
					t.Fatalf("expected LayerScanned to return true")
				}
			}
		})
	}
}

func Test_LayerScanned_Distribution_True(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of distributions to be associated with the scanartifacts and layer hash
		dists int
	}{
		{
			name:  "single scanner, single package",
			hash:  "test-layer-hash",
			scnrs: 1,
			dists: 1,
		},
		{
			name:  "4 scanners, 4 distributions",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 4,
		},
		{
			name:  "4 scanners, 8 distributions",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniqueDistributionScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			dists := test.GenUniqueDistributions(table.dists)
			err = pgtest.InsertDistributions(db, dists)

			err = pgtest.InsertDistScanArtifacts(db, table.hash, dists, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)
				if err != nil {
					t.Fatalf("received error checking if layer was scanned: %v", err)
				}
				if !b {
					t.Fatalf("expected LayerScanned to return true")
				}
			}
		})
	}
}

func Test_LayerScanned_Repository_True(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the layer's hash we are testing
		hash string
		// the number of scanners to create and linke with the layer_hash
		scnrs int
		// the number of repositories to be associated with the scanartifacts and layer hash
		dists int
	}{
		{
			name:  "single scanner, single repository",
			hash:  "test-layer-hash",
			scnrs: 1,
			dists: 1,
		},
		{
			name:  "4 scanners, 4 repository",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 4,
		},
		{
			name:  "4 scanners, 8 repository",
			hash:  "test-layer-hash",
			scnrs: 4,
			dists: 8,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			scnrs := test.GenUniqueRepositoryScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			repos := test.GenUniqueRepositories(table.dists)
			err = pgtest.InsertRepositories(db, repos)

			err = pgtest.InsertRepoScanArtifact(db, table.hash, repos, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			for _, scnr := range scnrs {
				b, err := store.LayerScanned(ctx, table.hash, scnr)
				if err != nil {
					t.Fatalf("received error checking if layer was scanned: %v", err)
				}
				if !b {
					t.Fatalf("expected LayerScanned to return true")
				}
			}
		})
	}
}
