package postgres

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
)

func Test_IndexReport_Success(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
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
				Hash:  "test-manifest-hash",
				State: "test-state",
				PackageIntroduced: map[int]string{
					160: "test-layer-hash",
				},
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
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			table.init(t, db, table.expectedSR, table.hash)

			sr, ok, err := store.IndexReport(ctx, table.hash)
			assert.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, table.expectedSR, sr)
		})
	}
}

func insertIndexReport(t *testing.T, db *sqlx.DB, sr *claircore.IndexReport, hash string) {
	_, err := db.Exec(`INSERT INTO indexreport (manifest_hash, scan_result) VALUES ($1, $2)`, hash, jsonbIndexReport(*sr))
	if err != nil {
		t.Fatalf("failed to insert test scan result: %v", err)
	}
}
