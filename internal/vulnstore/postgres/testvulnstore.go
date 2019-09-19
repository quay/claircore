package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
)

const (
	connString = "host=localhost port=5434 user=claircore dbname=claircore sslmode=disable"
	truncate   = `TRUNCATE updatecursor, vuln;`
)

func TestStore(ctx context.Context, t testing.TB) (*sqlx.DB, *Store, func()) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.Connect(ctx, connString)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// setup sqlx
	db, err := sqlx.Open("pgx", connString)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	s := NewVulnStore(db, pool)

	return db, s, func() {
		_, err := db.Exec(truncate)
		if err != nil {
			t.Fatalf("failed to truncate libcsan db tables. manual cleanup maybe necessary: %v", err)
		}
		db.Close()
	}
}
