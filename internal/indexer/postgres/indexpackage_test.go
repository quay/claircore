package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

// scanInfo is a helper struct for providing scanner information
// in test tables
type scnrInfo struct {
	name    string `integration:"name"`
	version string `integration:"version"`
	kind    string `integration:"kind"`
	id      int64  `integration:"id"`
}

func Test_IndexPackages_Success_Parallel(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		// the name of this benchmark
		name string
		// number of packages to index.
		pkgs int
		// the layer that holds the discovered packages
		layer *claircore.Layer
	}{
		{
			name: "10 packages",
			pkgs: 10,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "50 packages",
			pkgs: 50,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "100 packages",
			pkgs: 100,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "250 packages",
			pkgs: 250,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "500 packages",
			pkgs: 500,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "1000 packages",
			pkgs: 1000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "2000 packages",
			pkgs: 2000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "3000 packages",
			pkgs: 3000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
	}

	db, store, _, teardown := TestStore(ctx, t)
	defer teardown()

	// we will create a subtest which blocks the teardown() until
	// all parallel tests are finished
	t.Run("blocking-group", func(t *testing.T) {
		for _, tab := range tt {
			table := tab
			t.Run(table.name, func(t *testing.T) {
				t.Parallel()
				ctx, done := context.WithCancel(ctx)
				defer done()
				ctx = log.TestLogger(ctx, t)
				// gen a scnr and insert
				vscnrs := test.GenUniquePackageScanners(1)
				err := pgtest.InsertUniqueScanners(db, vscnrs)

				// gen packages
				pkgs := test.GenUniquePackages(table.pkgs)

				// run the indexing
				err = store.IndexPackages(ctx, pkgs, table.layer, vscnrs[0])
				if err != nil {
					t.Fatalf("failed to index packages: %v", err)
				}

				checkPackageScanArtifact(t, db, pkgs, table.layer)
			})
		}
	})
}

func Test_IndexPackages_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		// the name of this benchmark
		name string
		// number of packages to index.
		pkgs int
		// the layer that holds the discovered packages
		layer *claircore.Layer
	}{
		{
			name: "10 packages",
			pkgs: 10,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "50 packages",
			pkgs: 50,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "100 packages",
			pkgs: 100,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "250 packages",
			pkgs: 250,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "500 packages",
			pkgs: 500,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "1000 packages",
			pkgs: 1000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "2000 packages",
			pkgs: 2000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name: "3000 packages",
			pkgs: 3000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			// gen a scnr and insert
			vscnrs := test.GenUniquePackageScanners(1)
			err := pgtest.InsertUniqueScanners(db, vscnrs)

			// gen packages
			pkgs := test.GenUniquePackages(table.pkgs)

			// run the indexing
			err = store.IndexPackages(ctx, pkgs, table.layer, vscnrs[0])
			if err != nil {
				t.Fatalf("failed to index packages: %v", err)
			}

			checkPackageScanArtifact(t, db, pkgs, table.layer)
		})
	}

}

// checkScanArtifact confirms a scanartifact is created linking the layer, package/source/distribution entities from the layer, and scnr which discovered these.
// indirectly we test that dists and packages are indexed correctly by querying with their unique fields.
func checkPackageScanArtifact(t *testing.T, db *sqlx.DB, expectedPkgs []*claircore.Package, layer *claircore.Layer) {
	// NOTE: we gen one scanner for this test with ID 0, this is hard coded into this check
	for _, pkg := range expectedPkgs {
		var pkgID sql.NullInt64
		err := db.Get(
			&pkgID,
			`SELECT id FROM package 
			WHERE name = $1 
			AND kind = $2 
			AND version = $3`,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
		)
		if err != nil {
			t.Fatalf("received error selecting package id %s version %s", pkg.Name, pkg.Version)
		}

		var layer_hash, package_db, repository_hint string
		var package_id, source_id, scanner_id sql.NullInt64
		row := db.QueryRowx(
			`SELECT layer_hash, package_id, source_id, scanner_id, package_db, repository_hint
			FROM package_scanartifact 
			WHERE layer_hash = $1 
			AND package_id = $2 
			AND scanner_id = $3`,
			layer.Hash,
			pkgID,
			0,
		)

		err = row.Scan(&layer_hash, &package_id, &source_id, &scanner_id, &package_db, &repository_hint)
		if err != nil {
			if err == sql.ErrNoRows {
				t.Fatalf("failed to find scanartifact for pkg %v", pkg)
			}
			t.Fatalf("received error selecting scanartifact for pkg %v: %v", pkg, err)
		}

		if got, want := layer_hash, layer.Hash; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
		if got, want := package_id, pkgID; !got.Valid || got.Int64 != want.Int64 {
			t.Errorf("got: %v, want: %v", got, want)
		}
		if got, want := scanner_id, int64(0); !got.Valid || got.Int64 != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}
