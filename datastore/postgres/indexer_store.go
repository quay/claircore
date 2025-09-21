package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/indexer"
)

// InitPostgresIndexerStore initialize a indexer.Store given the pgxpool.Pool
func InitPostgresIndexerStore(_ context.Context, pool *pgxpool.Pool, doMigration bool) (indexer.Store, error) {
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer db.Close()

	// do migrations if requested
	if doMigration {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.IndexerMigrationTable
		err := migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	return NewIndexerStore(pool), nil
}

var _ indexer.Store = (*IndexerStore)(nil)

// IndexerStore implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type IndexerStore struct {
	pool     *pgxpool.Pool
	scanners map[string]int64
}

func NewIndexerStore(pool *pgxpool.Pool) *IndexerStore {
	return &IndexerStore{
		pool:     pool,
		scanners: make(map[string]int64),
	}
}

func (s *IndexerStore) Close(_ context.Context) error {
	s.pool.Close()
	return nil
}

func promTimer(h *prometheus.HistogramVec, name string, err *error) func() time.Duration {
	t := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		h.WithLabelValues(name, success(*err)).Observe(v)
	}))
	return t.ObserveDuration
}

func success(err error) string {
	if err == nil {
		return "true"
	}
	return "false"
}
