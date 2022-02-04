package libindex

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/postgres"
	"github.com/quay/claircore/libindex/migrations"
	"github.com/quay/claircore/pkg/poolstats"
)

// initialize a postgres pgxpool.Pool based on the given libindex.Opts
func initDB(ctx context.Context, opts *Opts) (*pgxpool.Pool, error) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = 30
	const appnameKey = `application_name`
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params[appnameKey]; !ok {
		params[appnameKey] = `libindex`
	}

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	if err := prometheus.Register(poolstats.NewCollector(pool, "libindex")); err != nil {
		zlog.Info(ctx).Msg("pool metrics already registered")
	}

	return pool, nil
}

// initialize a indexer.Store given libindex.Opts
func initStore(_ context.Context, pool *pgxpool.Pool, opts *Opts) (indexer.Store, error) {
	cfg, err := pgx.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", stdlib.RegisterConnConfig(cfg))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// do migrations if requested
	if opts.Migrations {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.MigrationTable
		err := migrator.Exec(migrate.Up, migrations.Migrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := postgres.NewStore(pool)
	return store, nil
}
