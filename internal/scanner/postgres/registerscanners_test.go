package postgres

import (
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func Test_RegisterScanners_Success(t *testing.T) {

	var tt = []struct {
		// name of the test
		name string
		// scanners we will try to register
		scnrs []scnrInfo
		// function to initialize the database
		init func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo)
	}{
		{
			name: "no existing scanners",
			scnrs: []scnrInfo{
				scnrInfo{
					name:    "package-scanner-1",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			// no op for this test
			init: func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {},
		},
		{
			name: "scanner exists",
			scnrs: []scnrInfo{
				scnrInfo{
					name:    "package-scanner-1",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			init: func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {
				for _, scnr := range scnrs {
					_, err := db.Exec(`INSERT INTO scanner (name, version, kind) VALUES ($1, $2, $3);`, scnr.name, scnr.version, scnr.kind)
					if err != nil {
						t.Fatalf("failed to insert scanner into database")
					}
				}
			},
		},
		{
			name: "no existing scanners. multi scanners",
			scnrs: []scnrInfo{
				scnrInfo{
					name:    "package-scanner-1",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-2",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-3",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-4",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			// no op for this test
			init: func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {},
		},
		{
			name: "partial scanner exists",
			scnrs: []scnrInfo{
				scnrInfo{
					name:    "package-scanner-1",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-2",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-3",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-4",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			init: func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {
				// add half the scanners to confirm we only
				// register the ones necessaryw
				n := len(scnrs) / 2
				for i := 0; i < n; i++ {
					_, err := db.Exec(`INSERT INTO scanner (name, version, kind) VALUES ($1, $2, $3);`, scnrs[i].name, scnrs[i].version, scnrs[i].kind)
					if err != nil {
						t.Fatalf("failed to insert scanner into database")
					}
				}
			},
		},
		{
			name: "no existing scanners. multi scanners duplicates",
			scnrs: []scnrInfo{
				scnrInfo{
					name:    "package-scanner-1",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-2",
					version: "v0.0.1",
					kind:    "package",
				},
				scnrInfo{
					name:    "package-scanner-2",
					version: "v0.0.1",
					kind:    "package",
				},
			},
			// no op for this test
			init: func(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := NewTestStore(t)
			defer teardown()

			table.init(t, db, table.scnrs)

			// create scnr mocks
			var vscnrs = []scanner.VersionedScanner{}
			for _, scnr := range table.scnrs {
				m := scanner.NewPackageScannerMock(scnr.name, scnr.version, scnr.kind)
				vscnrs = append(vscnrs, scanner.VersionedScanner(m))
			}

			err := store.RegisterScanners(vscnrs)
			assert.NoError(t, err)
			checkScanners(t, db, table.scnrs)
		})
	}
}

func checkScanners(t *testing.T, db *sqlx.DB, scnrs []scnrInfo) {
	for _, scnr := range scnrs {
		var id sql.NullInt64
		var name, version, kind string

		rows, err := db.Queryx(`SELECT id, name, version, kind FROM scanner WHERE name = $1 AND version = $2 AND kind = $3;`, scnr.name, scnr.version, scnr.kind)
		if err != nil {
			t.Fatalf("failed to select rows for scnr %v: %v", scnr, err)
		}

		var i int
		for rows.Next() {
			if i > 0 {
				t.Fatalf("query for scnr %v returned more then one row", scnr)
			}

			err := rows.Scan(&id, &name, &version, &kind)
			if err != nil {
				t.Fatalf("failed to scan test scnr %v: %v", scnr, err)
			}
		}

		if !id.Valid {
			t.Fatalf("id for scnr %v not valid", scnr)
		}
		assert.Equal(t, scnr.name, name)
		assert.Equal(t, scnr.version, version)
		assert.Equal(t, scnr.kind, kind)
	}
}
