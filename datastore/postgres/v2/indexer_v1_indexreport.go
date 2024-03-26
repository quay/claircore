package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// IndexReport implements [indexer.Store].
func (s *IndexerV1) IndexReport(ctx context.Context, hash claircore.Digest) (_ *claircore.IndexReport, exists bool, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	// All the "real" work in this method is shoved into database hooks (see
	// types_indexreport.go) and the function helpers (see metrics.go).

	var ir claircore.IndexReport
	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `cached`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		return c.QueryRow(ctx, query, hash).Scan(&ir)
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	default:
		return nil, false, err
	}
	return &ir, true, nil
}

func (s *IndexerV1) setIndexReport(ctx context.Context, ir *claircore.IndexReport) func(pgx.Tx) error {
	return s.callfile(ctx, `helper_cache_indexreport.sql`, `setindexreport`, func(ctx context.Context, tx pgx.Tx, query string) error {
		_, err := tx.Exec(ctx, query, ir.Hash, ir)
		return err
	})
}

// SetIndexReport implements [indexer.Store].
func (s *IndexerV1) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `SetIndexReport`, func(ctx context.Context, tx pgx.Tx) error {
		return pgx.BeginFunc(ctx, tx, s.setIndexReport(ctx, ir))
	}))
	if err != nil {
		return err
	}
	return nil
}

// SetIndexFinished implements [indexer.Store].
func (s *IndexerV1) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, vs indexer.VersionedScanners) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	rvs := rotateVersionedScanners(vs)
	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `SetIndexFinished`, func(ctx context.Context, tx pgx.Tx) (err error) {
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insertmanifest`, func(ctx context.Context, tx pgx.Tx, query string) error {
			_, err := tx.Exec(ctx, query, ir.Hash, rvs.Name, rvs.Version, rvs.Kind)
			return err
		}))
		if err != nil {
			return err
		}

		err = pgx.BeginFunc(ctx, tx, s.setIndexReport(ctx, ir))
		return err
	}))
	return err
}
