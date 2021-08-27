package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore/internal/indexer"
)

var _ indexer.Store = (*store)(nil)

// Store implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *store {
	return &store{
		pool: pool,
	}
}

func (s *store) Close(_ context.Context) error {
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
