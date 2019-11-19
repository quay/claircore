package postgres

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"

	"github.com/stretchr/testify/assert"
)

func Test_SetScanReport_StateUpdate(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []struct {
		// the name of the test
		name string
		// a ScanReport holding the initial state of the db
		initState *claircore.ScanReport
		// a ScanReport holding the state we want to transition to
		transitionState *claircore.ScanReport
	}{
		{
			name: "single package. no nested source",
			initState: &claircore.ScanReport{
				Hash:  "test-manifest-hash",
				State: "initial-state",
			},
			transitionState: &claircore.ScanReport{
				Hash:  "test-manifest-hash",
				State: "transitioned-state",
			},
		},
	}
	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			err := store.SetScanReport(ctx, table.initState)
			assert.NoError(t, err)

			sr := getScanReport(t, db, table.initState.Hash)
			assert.Equal(t, table.initState.State, sr.State)

			err = store.SetScanReport(ctx, table.transitionState)
			assert.NoError(t, err)

			sr = getScanReport(t, db, table.initState.Hash)
			assert.Equal(t, table.transitionState.State, sr.State)
		})
	}
}

func getScanReport(t *testing.T, db *sqlx.DB, hash string) claircore.ScanReport {
	// jsonbScanReport is a type definition based on scanner.ScanReport but with jsonb Value/Scan methods
	var sr jsonbScanReport
	row := db.QueryRow(`SELECT scan_result FROM scanreport WHERE manifest_hash = $1`, hash)
	err := row.Scan(&sr)
	if err != nil {
		t.Fatalf("failed to get scan result: %v", err)
	}
	return claircore.ScanReport(sr)
}

func Test_SetScanReport_Success(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []struct {
		// the name of the test
		name string
		// the scan result to be set
		sr *claircore.ScanReport
	}{
		{
			name: "single package. no nested source",
			sr: &claircore.ScanReport{
				Hash:  "test-manifest-hash",
				State: "test-state",
				PackageIntroduced: map[int]string{
					160: "test-layer-hash",
				},
				Success: true,
				Err:     "",
			},
		},
		{
			name: "single package nested source",
			sr: &claircore.ScanReport{
				Hash:  "test-manifest-hash",
				State: "test-state",
				PackageIntroduced: map[int]string{
					160: "test-layer-hash",
				},
				Success: true,
				Err:     "",
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			_, store, teardown := TestStore(ctx, t)
			defer teardown()

			err := store.SetScanReport(ctx, table.sr)
			assert.NoError(t, err)
		})
	}
}
