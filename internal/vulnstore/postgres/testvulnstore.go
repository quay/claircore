// +build integration

package postgres

import (
	"testing"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/stdlib"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

const (
	connString = "host=localhost port=5435 user=libvuln dbname=libvuln sslmode=disable"
	truncate   = `TRUNCATE updatecursor, vuln;`
)

func NewBenchStore(b *testing.B) (*sqlx.DB, *Store, func()) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	connconfig, err := pgx.ParseConnectionString(connString)
	if err != nil {
		b.Fatalf("failed to parse conn string: %v", err)
	}
	pool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		ConnConfig:     connconfig,
		MaxConnections: 30,
		AfterConnect:   nil,
		AcquireTimeout: 0,
	})
	if err != nil {
		b.Fatalf("failed to create connpool: %v", err)
	}

	// setup sqlx
	db := stdlib.OpenDBFromPool(pool)
	sqlxDB := sqlx.NewDb(db, "pgx")

	s := NewVulnStore(sqlxDB, pool)

	return sqlxDB, s, func() {
		_, err := db.Exec(truncate)
		if err != nil {
			b.Fatalf("failed to truncate libcsan db tables. manual cleanup maybe necessary: %v", err)
		}
		db.Close()
	}
}

func NewTestStore(t *testing.T) (*sqlx.DB, *Store, func()) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	connconfig, err := pgx.ParseConnectionString(connString)
	if err != nil {
		t.Fatalf("failed to parse conn string: %v", err)
	}
	pool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		ConnConfig:     connconfig,
		MaxConnections: 30,
		AfterConnect:   nil,
		AcquireTimeout: 0,
	})
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}

	// setup sqlx
	db := stdlib.OpenDBFromPool(pool)
	sqlxDB := sqlx.NewDb(db, "pgx")

	s := NewVulnStore(sqlxDB, pool)

	return sqlxDB, s, func() {
		_, err := db.Exec(truncate)
		if err != nil {
			t.Fatalf("failed to truncate libcsan db tables. manual cleanup maybe necessary: %v", err)
		}
		db.Close()
	}
}
