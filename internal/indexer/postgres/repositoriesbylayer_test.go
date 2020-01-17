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

func Test_RepositoriesByLayer_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// name of the test
		name string
		// the layer hash we want to test
		hash string
		// number repos to create
		repos int
		// number scnrs to create
		scnrs int
	}{
		{
			name:  "10 repos, 5 scanners",
			hash:  "test-layer-hash",
			repos: 10,
			scnrs: 5,
		},
		{
			name:  "50 repos, 25 scanners",
			hash:  "test-layer-hash",
			repos: 50,
			scnrs: 25,
		},
		{
			name:  "100 repos, 50 scanners",
			hash:  "test-layer-hash",
			repos: 100,
			scnrs: 50,
		},
		{
			name:  "500 repos, 250 scanners",
			hash:  "test-layer-hash",
			repos: 500,
			scnrs: 250,
		},
		{
			name:  "1000 repos, 500 scanners",
			hash:  "test-layer-hash",
			repos: 1000,
			scnrs: 500,
		},
		{
			name:  "2000 repos, 1000 scanners",
			hash:  "test-layer-hash",
			repos: 2000,
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
			repos := test.GenUniqueRepositories(table.repos)

			// index them into the database
			err := pgtest.InsertRepositories(db, repos)
			if err != nil {
				t.Fatalf("failed to insert repos: %v", err)
			}

			// create scnr mocks
			vscnrs := test.GenUniqueRepositoryScanners(table.scnrs)
			err = pgtest.InsertUniqueScanners(db, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scnrs: %v", err)
			}

			// create scanartifacts
			err = pgtest.InsertRepoScanArtifact(db, table.hash, repos, vscnrs)
			if err != nil {
				t.Fatalf("failed to insert scan artifacts for test: %v", err)
			}

			returnedRepos, err := store.RepositoriesByLayer(ctx, table.hash, vscnrs)

			sort.SliceStable(repos,
				func(i, j int) bool { return repos[i].ID < repos[j].ID })
			sort.SliceStable(returnedRepos,
				func(i, j int) bool { return returnedRepos[i].ID < returnedRepos[j].ID })

			if !cmp.Equal(repos, returnedRepos) {
				diff := cmp.Diff(repos, returnedRepos)
				t.Fatalf("security databases were not equal: \n%v", diff)
			}
		})
	}
}
