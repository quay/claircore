package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// LayerScanned implements [indexer.Store].
func (s *IndexerV1) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (ok bool, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `query`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		return c.QueryRow(ctx, query, scnr.Name(), scnr.Version(), scnr.Kind(), hash).Scan(&ok)
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	default:
		return false, err
	}

	return ok, nil
}

// SetLayerScanned implements [indexer.Store].
func (s *IndexerV1) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	ctx = zlog.ContextWithValues(ctx,
		"scanner", vs.Name(),
	)

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `insert`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		_, err := s.pool.Exec(ctx, query, hash, vs.Name(), vs.Version(), vs.Kind())
		return err
	}))
	if err != nil {
		return err
	}
	return nil
}
