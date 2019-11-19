package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/stretchr/testify/assert"
)

func Test_IndexRepositories_Success(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	tt := []struct {
		// the name of this benchmark
		name string
		// number of packages to index.
		repos int
		// the layer that holds the discovered packages
		layer *claircore.Layer
	}{
		{
			name:  "10 packages",
			repos: 10,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "50 packages",
			repos: 50,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "100 packages",
			repos: 100,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "250 packages",
			repos: 250,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "500 packages",
			repos: 500,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "1000 packages",
			repos: 1000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "2000 packages",
			repos: 2000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
		{
			name:  "3000 packages",
			repos: 3000,
			layer: &claircore.Layer{
				Hash: "test-layer-hash",
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			// gen a scnr and insert
			vscnrs := test.GenUniqueRepositoryScanners(1)
			err := pgtest.InsertUniqueScanners(db, vscnrs)

			// gen packages
			repos := test.GenUniqueRepositories(table.repos)

			// run the indexing
			err = store.IndexRepositories(ctx, repos, table.layer, vscnrs[0])
			if err != nil {
				t.Fatalf("failed to index repository: %v", err)
			}

			assert.NoError(t, err)
			checkRepoScanArtifact(t, db, repos, table.layer)
		})
	}

}

// checkRepoScanArtifact confirms a scanartifact is created linking the layer, repo entities from the layer, and scnr which discovered these.
// indirectly we test that repos are indexed correctly by querying with their unique fields.
func checkRepoScanArtifact(t *testing.T, db *sqlx.DB, expectedRepos []*claircore.Repository, layer *claircore.Layer) {
	// NOTE: we gen one scanner for this test with ID 0, this is hard coded into this check
	for _, repo := range expectedRepos {
		var repoID sql.NullInt64
		err := db.Get(
			&repoID,
			`SELECT id FROM repo
			WHERE name = $1
			AND key = $2
			AND uri = $3`,
			repo.Name,
			repo.Key,
			repo.URI,
		)
		if err != nil {
			t.Fatalf("failed to query for repository %v: %v", repo, err)
		}

		var layer_hash string
		var repo_id, scanner_id sql.NullInt64
		row := db.QueryRowx(
			`SELECT layer_hash, repo_id, scanner_id 
			FROM repo_scanartifact 
			WHERE layer_hash = $1 
			AND repo_id = $2 
			AND scanner_id = $3`,
			layer.Hash,
			repoID,
			0,
		)

		err = row.Scan(&layer_hash, &repo_id, &scanner_id)
		if err != nil {
			if err == sql.ErrNoRows {
				t.Fatalf("failed to find scanartifact for dist %v", repo)
			}
			t.Fatalf("received error selecting scanartifact for dist %v: %v", repo, err)
		}

		assert.Equal(t, layer.Hash, layer_hash)
		assert.Equal(t, repoID.Int64, repo_id.Int64)
		assert.Equal(t, int64(0), scanner_id.Int64)
	}
}
