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

func TestMatcherDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
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
	mdb := stdlib.OpenDB(*cfg.ConnConfig)
	defer mdb.Close()
	// run migrations
	migrator := migrate.NewPostgresMigrator(mdb)
	migrator.Table = migrations.MatcherMigrationTable
	err = migrator.Exec(migrate.Up, migrations.MatcherMigrations...)
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		db.Close(ctx, t)
	})
	return pool
}
