package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/pgx/v5/tracelog"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/datastore/postgres/types"
	"github.com/quay/claircore/test/integration"
)

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

type dbFlavor uint

const (
	_ dbFlavor = iota
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
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   testingadapter.NewLogger(t),
		LogLevel: tracelog.LogLevelError,
	}
	cfg.AfterConnect = types.ConnectRegisterTypes
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
	}
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
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
