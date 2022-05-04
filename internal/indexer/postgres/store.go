package postgres

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/quay/claircore/internal/indexer"
)

var _ indexer.Store = (*store)(nil)

// Store implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type store struct {
	pool *pgxpool.Pool
}

// NewStore returns an initialized object implementing the [indexer.Store] interface.
//
// Close must be called or the program may panic.
func NewStore(pool *pgxpool.Pool) *store {
	s := &store{
		pool: pool,
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(s, func(s *store) {
		panic(fmt.Sprintf("%s:%d: store not closed", file, line))
	})
	return s
}

// Close tears down the store.
func (s *store) Close(_ context.Context) error {
	runtime.SetFinalizer(s, nil)
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

func (s *store) selectScanners(ctx context.Context, vs indexer.VersionedScanners) ([]int64, error) {
	ids := make([]int64, len(vs))
	for i, v := range vs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		err := s.pool.QueryRow(ctx, selectScanner, v.Name(), v.Version(), v.Kind()).
			Scan(&ids[i])
		done()
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
