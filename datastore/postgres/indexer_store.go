package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/indexer"
)

// InitPostgresIndexerStore initialize a indexer.Store given the pgxpool.Pool
func InitPostgresIndexerStore(ctx context.Context, pool *pgxpool.Pool, doMigration bool) (indexer.Store, error) {
	if doMigration {
		if err := migrations.Indexer(ctx, pool.Config().ConnConfig); err != nil {
			return nil, err
		}
		// Potentially added types, make sure any connections pulled from this
		// pool are configured properly going forward.
		pool.Reset()
	}

	return NewIndexerStore(pool), nil
}

var _ indexer.Store = (*IndexerStore)(nil)

// IndexerStore implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type IndexerStore struct {
	pool     *pgxpool.Pool
	scanners sync.Map
}

func NewIndexerStore(pool *pgxpool.Pool) *IndexerStore {
	return &IndexerStore{
		pool: pool,
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
