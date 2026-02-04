package postgres

import (
	"context"
	"fmt"
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

	store := NewIndexerStore(pool)
	return store, nil
}

var _ indexer.Store = (*IndexerStore)(nil)

// IndexerStore implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type IndexerStore struct {
	pool *pgxpool.Pool
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

const selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`

func (s *IndexerStore) selectScanners(ctx context.Context, vs indexer.VersionedScanners) ([]int64, error) {
	ids := make([]int64, len(vs))
	for i, v := range vs {
		err := s.pool.QueryRow(ctx, selectScanner, v.Name(), v.Version(), v.Kind()).
			Scan(&ids[i])
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve id for scanner %q: %w", v.Name(), err)
		}
	}

	return ids, nil
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
