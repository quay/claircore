package postgres

import (
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"

	"github.com/stretchr/testify/assert"
)

func Test_ScanReport_Success(t *testing.T) {
	integration.Skip(t)
	var tt = []struct {
		// the name of the test
		name string
		// the hash to lookup
		hash string
		// the expected scan result
		expectedSR *claircore.ScanReport
		// initialize the database. this test requires us to
		// create the ScanReport
		init func(t *testing.T, db *sqlx.DB, sr *claircore.ScanReport, hash string)
	}{
		{
			name: "full scan result",
			hash: "test-manifest-hash",
			expectedSR: &claircore.ScanReport{
				Hash:  "test-manifest-hash",
				State: "test-state",
				PackageIntroduced: map[int]string{
					160: "test-layer-hash",
				},
				Success: true,
				Err:     "",
			},
			init: func(t *testing.T, db *sqlx.DB, sr *claircore.ScanReport, hash string) {
				insertScanReport(t, db, sr, hash)
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := NewTestStore(t)
			defer teardown()

			table.init(t, db, table.expectedSR, table.hash)

			sr, ok, err := store.ScanReport(table.hash)
			assert.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, table.expectedSR, sr)
		})
	}
}

func insertScanReport(t *testing.T, db *sqlx.DB, sr *claircore.ScanReport, hash string) {
	_, err := db.Exec(`INSERT INTO scanreport (manifest_hash, scan_result) VALUES ($1, $2)`, hash, jsonbScanReport(*sr))
	if err != nil {
		t.Fatalf("failed to insert test scan result: %v", err)
	}
}
