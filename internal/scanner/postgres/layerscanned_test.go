package postgres

import (
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"

	"github.com/stretchr/testify/assert"
)

// Test_LayerScanner_False tests that we correctly
// identify if a layer has not been scanned by a particular versioned scanner
func Test_LayerScanned_False(t *testing.T) {
	integration.Skip(t)
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
			db, store, teardown := NewTestStore(t)
			defer teardown()

			// create scanners
			scnrs := test.GenUniqueScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			// create packages
			pkgs := test.GenUniquePackages(table.pkgs)
			err = pgtest.InsertPackages(db, pkgs)

			// for each scanner confirm we see the layer as scanned
			for _, scnr := range scnrs {
				b, err := store.LayerScanned(table.hash, scnr)

				assert.NoError(t, err)
				assert.False(t, b)
			}

		})
	}
}

// Test_LayerScanner_True tests that we correctly
// identify if a layer has been scanned by a particular versioned scanner
func Test_LayerScanned_True(t *testing.T) {
	integration.Skip(t)
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
			db, store, teardown := NewTestStore(t)
			defer teardown()

			// create scanners
			scnrs := test.GenUniqueScanners(table.scnrs)
			err := pgtest.InsertUniqueScanners(db, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			// create packages
			pkgs := test.GenUniquePackages(table.pkgs)
			err = pgtest.InsertPackages(db, pkgs)

			// create scanartifacts
			err = pgtest.InsertScanArtifacts(db, table.hash, pkgs, scnrs)
			if err != nil {
				t.Fatalf("failed to insert unique scanners: %v", err)
			}

			// for each scanner confirm we see the layer as scanned
			for _, scnr := range scnrs {
				b, err := store.LayerScanned(table.hash, scnr)

				assert.NoError(t, err)
				assert.True(t, b)
			}

		})
	}
}
