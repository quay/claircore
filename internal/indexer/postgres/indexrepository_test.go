package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Test_IndexRepositories_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	layer := test.ServeLayers(ctx, t, 1)

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
			layer: layer[0],
		},
		{
			name:  "50 packages",
			repos: 50,
			layer: layer[0],
		},
		{
			name:  "100 packages",
			repos: 100,
			layer: layer[0],
		},
		{
			name:  "250 packages",
			repos: 250,
			layer: layer[0],
		},
		{
			name:  "500 packages",
			repos: 500,
			layer: layer[0],
		},
		{
			name:  "1000 packages",
			repos: 1000,
			layer: layer[0],
		},
		{
			name:  "2000 packages",
			repos: 2000,
			layer: layer[0],
		},
		{
			name:  "3000 packages",
			repos: 3000,
			layer: layer[0],
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			// gen a scnr and insert
			vscnrs := test.GenUniqueRepositoryScanners(1)
			err := pgtest.InsertUniqueScanners(db, vscnrs)

			// gen packages
			repos := test.GenUniqueRepositories(table.repos, func(r *claircore.Repository) {
				r.URI = layer[0].URI
			})

			// run the indexing
			err = store.IndexRepositories(ctx, repos, table.layer, vscnrs[0])
			if err != nil {
				t.Fatalf("failed to index repository: %v", err)
			}

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
		t.Logf("SELECT .. name = %q, key = %q, uri = %q", repo.Name, repo.Key, repo.URI)
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
		if !repoID.Valid {
			t.Fatal("invalid repo id")
		}
		t.Logf("repo id: %d", repoID.Int64)

		var layer_hash claircore.Digest
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

		if got, want := layer_hash, layer.Hash; !cmp.Equal(got, want, cmp.AllowUnexported(claircore.Digest{})) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := repo_id, repoID; !got.Valid || got.Int64 != want.Int64 {
			t.Errorf("got: %v, want: %v", got, want)
		}
		if got, want := scanner_id, int64(0); !got.Valid || got.Int64 != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}
