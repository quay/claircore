package libscan

import (
	"context"
	"fmt"

	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/postgres"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
)

// initialize a scanner.Store given libscan.Opts
func initStore(ctx context.Context, opts *Opts) (*sqlx.DB, scanner.Store, error) {
	var store scanner.Store
	switch opts.DataStore {
	case Postgres:
		// we are going to use pgx for more control over connection pool and
		// and a cleaner api around bulk inserts
		cfg, err := pgxpool.ParseConfig(opts.ConnString)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ConnString: %v", err)
		}
		cfg.MaxConns = 30
		pool, err := pgxpool.ConnectConfig(ctx, cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ConnPool: %v", err)
		}

		// setup sqlx
		db, err := sqlx.Open("pgx", opts.ConnString)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open db: %v", err)
		}

		// we could use the `WithTracer` here to reuse the same tracer,
		// but we probably want a new service name for the storage layer
		store = postgres.NewStore(db, pool)
		return db, store, nil
	default:
		return nil, nil, fmt.Errorf("provided unknown DataStore")
	}
}
