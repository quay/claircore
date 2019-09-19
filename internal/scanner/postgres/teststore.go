package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
)

const (
	connString = "host=localhost port=5434 user=claircore dbname=claircore sslmode=disable"
	Truncate   = `TRUNCATE dist, package, scanner, scannerlist, scanartifact, scanreport;`
)

func TestStore(ctx context.Context, t testing.TB) (*sqlx.DB, *store, func()) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		t.Fatalf("failed to parse conn string: %v", err)
	}
	cfg.MaxConns = 30
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}

	db, err := sqlx.Open("pgx", connString)
	if err != nil {
		t.Fatalf("failed to sqlx Open: %v", err)
	}

	s := NewStore(db, pool)

	return db, s, func() {
		_, err := db.Exec(Truncate)
		if err != nil {
			t.Fatalf("failed to truncate libcsan db tables. manual cleanup maybe necessary: %v", err)
		}
		db.Close()
	}
}
