package postgres

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_SetScanFinished_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	// function to initialize database. we must add all scanners to they are available in the database. we must then
	// create scannlist records for any of the previousScnrs to prove we deleted them and linked the updatedScnrs
	var init = func(t *testing.T, db *sqlx.DB, hash string, previousScnrs []scnrInfo, updatedScnrs []scnrInfo) {
		var temp = []scnrInfo{}
		temp = append(temp, previousScnrs...)
		temp = append(temp, updatedScnrs...)

		for _, scnr := range temp {
			// insert scanner
			_, err := db.Exec(`INSERT INTO scanner (id, name, version, kind) VALUES ($1, $2, $3, $4)`, scnr.id, scnr.name, scnr.version, scnr.kind)
			if err != nil {
				t.Fatalf("failed to insert set scanner %v: %v", scnr, err)
			}
		}

		// create scannlist for previousScnrs if any
		for _, scnr := range previousScnrs {
			// insert scannerlist
			_, err := db.Exec(`INSERT INTO scannerlist (manifest_hash, scanner_list) VALUES ($1, $2)`, hash, scnr.id)
			if err != nil {
				t.Fatalf("failed to insert set scanner %v: %v", scnr, err)
			}
		}
	}

	var tt = []struct {
		// the name of this test
		name string
		// the manifest hash we are setting scanners for
		hash string
		// scnrs to insert for initialization information
		previousScnrs []scnrInfo
		// scnrs to call store.SetScannerList
		updatedScnrs []scnrInfo
		// initialize our database
		init func(t *testing.T, db *sqlx.DB, hash string, previousScnrs []scnrInfo, updatedScnrs []scnrInfo)
	}{
		{
			name:          "no previous scanners",
			hash:          "test-manifest-hash",
			previousScnrs: []scnrInfo{},
			updatedScnrs: []scnrInfo{
				scnrInfo{
					id:      170,
					name:    "package-scanner-10",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					id:      171,
					name:    "package-scanner-11",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					id:      172,
					name:    "package-scanner-12",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			init: init,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			table.init(t, db, table.hash, table.previousScnrs, table.updatedScnrs)

			// create scnr mocks
			var scnrs = indexer.VersionedScanners{}
			temp := []indexer.PackageScanner{}
			for _, scnr := range table.updatedScnrs {
				m := indexer.NewPackageScannerMock(scnr.name, scnr.version, scnr.kind)
				temp = append(temp, m)
			}
			scnrs.PStoVS(temp)
			t.Log(scnrs)

			err := store.SetIndexFinished(ctx, &claircore.IndexReport{
				Hash: table.hash,
			}, scnrs)
			if err != nil {
				t.Fatal(err)
			}

			checkUpdatedScannerList(t, db, table.hash, table.updatedScnrs)

			sr := getIndexReport(t, db, table.hash)
			assert.Equal(t, table.hash, sr.Hash)
		})
	}
}

func checkUpdatedScannerList(t *testing.T, db *sqlx.DB, hash string, updatedScnrs []scnrInfo) {
	var foundIDs []int64
	err := db.Select(&foundIDs, `SELECT scanner_id FROM scannerlist WHERE manifest_hash = $1`, hash)
	if err != nil {
		t.Fatalf("failed to select test scanner ids for manifest %v: %v", hash, err)
	}

	var expectedIDs []int64
	for _, scnr := range updatedScnrs {
		expectedIDs = append(expectedIDs, scnr.id)
	}

	assert.ElementsMatch(t, expectedIDs, foundIDs)
}
