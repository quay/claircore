package libscan

import (
	"fmt"
	"time"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/postgres"
)

// initialize a scanner.Store given libscan.Opts
func initStore(opts *Opts) (*sqlx.DB, scanner.Store, error) {
	var store scanner.Store
	switch opts.DataStore {
	case Postgres:
		// we are going to use pgx for more control over connection pool and
		// and a cleaner api around bulk inserts
		connconfig, err := pgx.ParseConnectionString(opts.ConnString)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ConnString: %v", err)
		}
		pool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
			ConnConfig:     connconfig,
			MaxConnections: 30,
			AfterConnect:   nil,
			AcquireTimeout: 30 * time.Second,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ConnPool: %v", err)
		}

		// setup sqlx
		db := stdlib.OpenDBFromPool(pool)
		sqlxDB := sqlx.NewDb(db, "pgx")

		store = postgres.NewStore(sqlxDB, pool)
		return sqlxDB, store, nil
	default:
		return nil, nil, fmt.Errorf("provided unknown DataStore")
	}
}
