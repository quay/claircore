package libindex

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/libindex/migrations"
)

// InitPostgresStore initialize a indexer.Store given libindex.Opts
func InitPostgresStore(_ context.Context, pool *pgxpool.Pool, doMigration bool) (indexer.Store, error) {
	cfg, err := pgx.ParseConfig(pool.Config().ConnConfig.ConnString())
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", stdlib.RegisterConnConfig(cfg))
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close()

	// do migrations if requested
	if doMigration {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.MigrationTable
		err := migrator.Exec(migrate.Up, migrations.Migrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := postgres.NewIndexerStore(pool)
	return store, nil
}
