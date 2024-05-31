package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/test/integration"
)

// MinVersion is minimum needed PostgreSQL version, in the integer format.
const MinVersion uint64 = 150000

// TestMatcherDB returns a [pgxpool.Pool] connected to a started and configured
// for a Matcher database.
//
// If any errors are encountered, the test is failed and exited.
func TestMatcherDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDB(ctx, t, dbMatcher)
}

// TestIndexerDB returns a [pgxpool.Pool] connected to a started and configured
// for a Indexer database.
//
// If any errors are encountered, the test is failed and exited.
func TestIndexerDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDB(ctx, t, dbIndexer)
}

// TestDB returns a [pgxpool.Pool] connected to a started and configured
// database that has not had any migrations run.
//
// If any errors are encountered, the test is failed and exited.
func TestDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDB(ctx, t, dbNone)
}

type dbFlavor uint

const (
	dbNone dbFlavor = iota
	dbMatcher
	dbIndexer
)

func testDB(ctx context.Context, t testing.TB, which dbFlavor) *pgxpool.Pool {
	t.Helper()
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	checkVersion(ctx, t, pool)

	mdb := stdlib.OpenDB(*cfg.ConnConfig)
	defer mdb.Close()
	// run migrations
	migrator := migrate.NewPostgresMigrator(mdb)
	switch which {
	case dbMatcher:
		migrator.Table = migrations.MatcherMigrationTable
		err = migrator.Exec(migrate.Up, migrations.MatcherMigrations...)
	case dbIndexer:
		migrator.Table = migrations.IndexerMigrationTable
		err = migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
	case dbNone:
	default:
		err = fmt.Errorf("unknown flavor: %v", which)
	}
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}
	loadHelpers(ctx, t, pool, which)

	// BUG(hank) The Test*DB functions close over the passed-in Context and use
	// it for the Cleanup method. Because Cleanup functions are earlier in the
	// stack than any defers inside the test, make sure the Context isn't one
	// that's deferred to be canceled.
	t.Cleanup(func() {
		pool.Close()
		db.Close(ctx, t)
	})
	return pool
}

func checkVersion(ctx context.Context, t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	var vs string
	err := pool.QueryRow(ctx, `SELECT current_setting('server_version_num');`).Scan(&vs)
	if err != nil {
		t.Fatal(err)
	}
	v, err := strconv.ParseUint(vs, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v < MinVersion {
		t.Fatalf("PostgreSQL version too old: %d < %d", v, MinVersion)
	}
	t.Logf("PostgreSQL version: %d", v)
}

//go:embed sql
var extraSQL embed.FS

// LoadHelpers loads extra SQL from both the "sql" directory in this package and
// the test package's "testdata" directory.
//
// The "flavor" argument selects which prefix is added onto the file glob.
func loadHelpers(ctx context.Context, t testing.TB, pool *pgxpool.Pool, flavor dbFlavor) {
	t.Helper()
	logprefix := [...]string{"global", "local"}
	var look []fs.FS
	if sys, err := fs.Sub(extraSQL, "sql"); err != nil {
		t.Fatalf("unexpected error from embed.FS: %v", err)
	} else {
		look = append(look, sys)
	}
	// NB This is relative to the test being run, _not_ this file. Because this
	// is a helper library, this is different than you may expect.
	if sys, err := fs.Sub(os.DirFS("."), "testdata"); err != nil {
		t.Log("no testdata directory, skipping local loading")
	} else {
		look = append(look, sys)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("unable to acquire connection: %v", err)
	}
	defer conn.Release()
	glob := []string{"all_*.psql"}
	switch flavor {
	case dbMatcher:
		glob = append(glob, "matcher_*.psql")
	case dbIndexer:
		glob = append(glob, "indexer_*.psql")
	}
	for i, sys := range look {
		for _, g := range glob {
			ms, err := fs.Glob(sys, g)
			if err != nil {
				panic(fmt.Sprintf("programmer error: %v", err))
			}
			for _, f := range ms {
				b, err := fs.ReadFile(sys, f)
				if err != nil {
					t.Error(err)
					continue
				}
				t.Logf("loading %s %q", logprefix[i], path.Base(f))
				if _, err := conn.Exec(ctx, string(b)); err != nil {
					t.Error(err)
				}
			}
		}
	}
}
