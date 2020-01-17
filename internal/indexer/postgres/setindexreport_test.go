package postgres

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_SetIndexReport_StateUpdate(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// a IndexReport holding the initial state of the db
		initState *claircore.IndexReport
		// a IndexReport holding the state we want to transition to
		transitionState *claircore.IndexReport
	}{
		{
			name: "single package. no nested source",
			initState: &claircore.IndexReport{
				Hash:  "test-manifest-hash",
				State: "initial-state",
			},
			transitionState: &claircore.IndexReport{
				Hash:  "test-manifest-hash",
				State: "transitioned-state",
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

			if err := store.SetIndexReport(ctx, table.initState); err != nil {
				t.Fatal(err)
			}

			sr := getIndexReport(t, db, table.initState.Hash)
			if got, want := sr.State, table.initState.State; got != want {
				t.Fatalf("got: %q, want: %q", got, want)
			}

			if err := store.SetIndexReport(ctx, table.transitionState); err != nil {
				t.Fatal(err)
			}

			sr = getIndexReport(t, db, table.initState.Hash)
			if got, want := sr.State, table.transitionState.State; got != want {
				t.Fatalf("got: %q, want: %q", got, want)
			}
		})
	}
}

func getIndexReport(t *testing.T, db *sqlx.DB, hash string) claircore.IndexReport {
	// jsonbIndexReport is a type definition based on scanner.IndexReport but with jsonb Value/Scan methods
	var sr jsonbIndexReport
	row := db.QueryRow(`SELECT scan_result FROM indexreport WHERE manifest_hash = $1`, hash)
	err := row.Scan(&sr)
	if err != nil {
		t.Fatalf("failed to get scan result: %v", err)
	}
	return claircore.IndexReport(sr)
}

func Test_SetIndexReport_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the scan result to be set
		sr *claircore.IndexReport
	}{
		{
			name: "single package. no nested source",
			sr: &claircore.IndexReport{
				Hash:    "test-manifest-hash",
				State:   "test-state",
				Success: true,
				Err:     "",
			},
		},
		{
			name: "single package nested source",
			sr: &claircore.IndexReport{
				Hash:    "test-manifest-hash",
				State:   "test-state",
				Success: true,
				Err:     "",
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			_, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			if err := store.SetIndexReport(ctx, table.sr); err != nil {
				t.Fatal(err)
			}
		})
	}
}
