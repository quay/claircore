package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib" // Needed for sql.Open
	"github.com/remind101/migrate"

	"github.com/quay/claircore/libindex/migrations"
	"github.com/quay/claircore/test/integration"
)

func TestDatabase(ctx context.Context, t testing.TB) (*pgxpool.Pool, func()) {
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

	dsn := fmt.Sprintf("host=%s port=%d database=%s user=%s", cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database, cfg.ConnConfig.User)
	t.Log(dsn)
	dbh, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed sql.Open: %v", err)
	}
	defer dbh.Close()

	// run migrations
	migrator := migrate.NewPostgresMigrator(dbh)
	migrator.Table = migrations.MigrationTable
	err = migrator.Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}

	return pool, func() {
		pool.Close()
		db.Close(ctx, t)
	}
}
