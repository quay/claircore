package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_RegisterScanners_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
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
						t.Fatalf("failed to insert scanner into database: %v", err)
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			table.init(t, db, table.scnrs)

			// create scnr mocks
			var vscnrs = []indexer.VersionedScanner{}
			for _, scnr := range table.scnrs {
				m := indexer.NewPackageScannerMock(scnr.name, scnr.version, scnr.kind)
				vscnrs = append(vscnrs, indexer.VersionedScanner(m))
			}

			if err := store.RegisterScanners(ctx, vscnrs); err != nil {
				t.Fatal(err)
			}
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

		for i := 0; rows.Next(); i++ {
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
		if got, want := name, scnr.name; got != want {
			t.Fatalf("got: %q, want: %q", got, want)
		}
		if got, want := version, scnr.version; got != want {
			t.Fatalf("got: %q, want: %q", got, want)
		}
		if got, want := kind, scnr.kind; got != want {
			t.Fatalf("got: %q, want: %q", got, want)
		}
	}
}
