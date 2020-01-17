package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_IndexReport_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the hash to lookup
		hash string
		// the expected scan result
		expectedSR *claircore.IndexReport
		// initialize the database. this test requires us to
		// create the IndexReport
		init func(t *testing.T, db *sqlx.DB, sr *claircore.IndexReport, hash string)
	}{
		{
			name: "full scan result",
			hash: "test-manifest-hash",
			expectedSR: &claircore.IndexReport{
				Hash:    "test-manifest-hash",
				State:   "test-state",
				Success: true,
				Err:     "",
			},
			init: func(t *testing.T, db *sqlx.DB, sr *claircore.IndexReport, hash string) {
				insertIndexReport(t, db, sr, hash)
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

			table.init(t, db, table.expectedSR, table.hash)

			sr, ok, err := store.IndexReport(ctx, table.hash)
			if err != nil {
				t.Error(err)
			}
			if !ok {
				t.Error("not OK")
			}
			if got, want := sr, table.expectedSR; !cmp.Equal(got, want) {
				t.Fatal(cmp.Diff(got, want))
			}
		})
	}
}

func insertIndexReport(t *testing.T, db *sqlx.DB, sr *claircore.IndexReport, hash string) {
	_, err := db.Exec(`INSERT INTO indexreport (manifest_hash, scan_result) VALUES ($1, $2)`, hash, jsonbIndexReport(*sr))
	if err != nil {
		t.Fatalf("failed to insert test scan result: %v", err)
	}
}
