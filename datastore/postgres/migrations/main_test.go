// Package migrations_test does blackbox testing for the database migrations.
//
// By default, it simply runs all the migrations.
// To run pure-SQL tests, add a txtar file in `${name}/migration_${NN}.txtar`
// (where `name` is "indexer" or "matcher" and `NN` is the relevant migration ID).
// Any comment in the txtar is executed before the files.
// Files in the txtar are executed in separate tests.
//
// Tests should make sure to add any test-only objects or functions to the "$user" schema.
// This schema is not cleared between tests, but previous tests may not have been run.
// Make sure to use `OR REPLACE` constructs for the test helpers.
package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func TestIndexer(t *testing.T) {
	doTests(t, `indexer`, migrations.IndexerMigrations)
}

func TestMatcher(t *testing.T) {
	doTests(t, `matcher`, migrations.MatcherMigrations)
}

func doTests(t *testing.T, n string, ms []migrate.Migration) {
	t.Helper()
	ctx := zlog.Test(context.Background(), t)
	integration.NeedDB(t)
	pool := pgtest.TestDB(ctx, t)

	mdb := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer mdb.Close()
	migrator := migrate.NewPostgresMigrator(mdb)

	for i, m := range ms {
		t.Run(fmt.Sprintf("%02d", i+1), func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			// Do it this way to let the `-run` flag work correctly.
			if err := migrator.Exec(migrate.Up, ms[:i+1]...); err != nil {
				t.Fatal(err)
			}

			arname := filepath.Join(n, `testdata`, fmt.Sprintf(`migration_%02d.txtar`, m.ID))
			_, err := os.Stat(arname)
			switch {
			case err == nil:
				t.Logf("running migration tests")
			case errors.Is(err, fs.ErrNotExist):
				t.Skip("no tests")
			default:
				t.Fatal(err)
			}
			ar, err := txtar.ParseFile(arname)
			if err != nil {
				t.Fatal(err)
			}

			runTests(t, ctx, pool, ar)
		})
	}
}

func runTests(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ar *txtar.Archive) {
	t.Helper()
	if len(ar.Comment) != 0 {
		t.Logf("loading helpers")
		cmd := string(ar.Comment)
		err := pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
			defer printFromLogID(t, ctx, conn, getLogID(t, ctx, conn))

			tag, err := conn.Exec(ctx, cmd)
			if err != nil {
				return err
			}
			t.Log(tag)
			return nil
		})
		if err != nil {
			t.Error(err)
			return
		}
	}
	for _, f := range ar.Files {
		t.Run(f.Name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			cmd := string(f.Data)
			err := pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
				defer printFromLogID(t, ctx, conn, getLogID(t, ctx, conn))

				tag, err := conn.Exec(ctx, cmd)
				if err != nil {
					return err
				}
				t.Log(tag)
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// This is a hack and will blow up in the future.

func getLogID(t *testing.T, ctx context.Context, conn *pgxpool.Conn) (id int64) {
	err := conn.QueryRow(ctx, `SELECT id FROM matcher_v2_meta.log ORDER BY id DESC LIMIT 1`).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Error(err)
		id = -1
	}
	return id
}

func printFromLogID(t *testing.T, ctx context.Context, conn *pgxpool.Conn, id int64) {
	rows, err := conn.Query(ctx, `SELECT ts, kind, message, event FROM matcher_v2_meta.log WHERE id > $1 ORDER BY id`, id)
	if err != nil {
		t.Log(err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	var st, prev, ts time.Time
	var kind, msg string
	var ev []byte
	tw := tabwriter.NewWriter(&b, 1, 0, 1, ' ', 0)
	for rows.Next() {
		if err := rows.Scan(&ts, &kind, &msg, &ev); err != nil {
			t.Error(err)
			continue
		}
		if st.IsZero() {
			st = ts
			prev = ts
		}
		fmt.Fprintf(tw, "%v\t+%v\t%s:\t%s\t%s\n", ts.Sub(st), ts.Sub(prev), kind, msg, string(ev))
		prev = ts
	}
	if err := rows.Err(); err != nil {
		t.Error(err)
	}
	tw.Flush()
	if b.Len() != 0 {
		t.Logf("database log messages:\n%s", b.String())
	}
}
