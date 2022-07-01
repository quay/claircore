package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/test/integration"
)

func TestIndexerDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}

	dbh := stdlib.OpenDB(*cfg.ConnConfig)
	defer dbh.Close()

	// run migrations
	migrator := migrate.NewPostgresMigrator(dbh)
	migrator.Table = migrations.IndexerMigrationTable
	err = migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}
	// BUG(hank) TestDatabase closes over the passed-in Context and uses it for
	// the Cleanup method. Because Cleanup functions are earlier in the stack
	// than any defers inside the test, make sure the Context isn't one that's
	// deferred to be cancelled.
	t.Cleanup(func() {
		pool.Close()
		db.Close(ctx, t)
	})

	return pool
}
