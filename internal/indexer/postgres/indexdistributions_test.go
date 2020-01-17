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

func Test_IndexDistributions_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		// the name of this benchmark
		name string
		// number of packages to index.
		dists int
		// the layer that holds the discovered packages
		layer *claircore.Layer
	}{
		{
			name:  "10 packages",
			dists: 10,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "50 packages",
			dists: 50,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "100 packages",
			dists: 100,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "250 packages",
			dists: 250,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "500 packages",
			dists: 500,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "1000 packages",
			dists: 1000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "2000 packages",
			dists: 2000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "3000 packages",
			dists: 3000,
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
			vscnrs := test.GenUniqueDistributionScanners(1)
			err := pgtest.InsertUniqueScanners(db, vscnrs)

			// gen packages
			dists := test.GenUniqueDistributions(table.dists)

			// run the indexing
			err = store.IndexDistributions(ctx, dists, table.layer, vscnrs[0])
			if err != nil {
				t.Fatalf("failed to index distributions: %v", err)
			}

			checkDistScanArtifact(t, db, dists, table.layer)
		})
	}

}

// checkScanArtifact confirms a scanartifact is created linking the layer, distribution entities from the layer, and scnr which discovered these.
// indirectly we test that dists are indexed correctly by querying with their unique fields.
func checkDistScanArtifact(t *testing.T, db *sqlx.DB, expectedDists []*claircore.Distribution, layer *claircore.Layer) {
	// NOTE: we gen one scanner for this test with ID 0, this is hard coded into this check
	for _, dist := range expectedDists {
		var distID sql.NullInt64
		err := db.Get(
			&distID,
			`SELECT id FROM dist
			WHERE name = $1
			AND did = $2
			AND version = $3
			AND version_code_name = $4
			AND version_id = $5
			AND arch = $6
			AND cpe = $7
			AND pretty_name = $8`,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
		)
		if err != nil {
			t.Fatalf("failed to query for distribution %v: %v", dist, err)
		}
		if !distID.Valid {
			t.Fatalf("distID not valid")
		}
		t.Logf("got distID %d", distID.Int64)

		var layer_hash string
		var dist_id, scanner_id sql.NullInt64
		row := db.QueryRowx(
			`SELECT layer_hash, dist_id, scanner_id 
			FROM dist_scanartifact 
			WHERE layer_hash = $1 
			AND dist_id = $2 
			AND scanner_id = $3`,
			layer.Hash,
			distID,
			0,
		)

		err = row.Scan(&layer_hash, &dist_id, &scanner_id)
		if err != nil {
			if err == sql.ErrNoRows {
				t.Fatalf("failed to find scanartifact for dist %v", dist)
			}
			t.Fatalf("received error selecting scanartifact for dist %v: %v", dist, err)
		}

		if got, want := layer_hash, layer.Hash; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
		if got, want := dist_id, distID; !got.Valid || got.Int64 != want.Int64 {
			t.Errorf("got: %v, want: %v", got, want)
		}
		if got, want := scanner_id, int64(0); !got.Valid || got.Int64 != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}
