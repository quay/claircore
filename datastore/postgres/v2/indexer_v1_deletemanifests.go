package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

// DeleteManifests implements [indexer.Store].
func (s *IndexerV1) DeleteManifests(ctx context.Context, d ...claircore.Digest) (out []claircore.Digest, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	out = make([]claircore.Digest, 0, len(d))
	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `DeleteManifests`, func(ctx context.Context, tx pgx.Tx) (err error) {
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `deleteManifests`, deleteManifests(&out, d)))
		if err != nil {
			return err
		}
		zlog.Debug(ctx).
			Int("count", len(out)).
			Int("nonexistant", len(d)-len(out)).
			Msg("deleted manifests")
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `layerCleanup`, layerCleanup))
		if err != nil {
			return err
		}
		return nil
	}))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deleteManifests(out *[]claircore.Digest, ds []claircore.Digest) callFunc {
	return func(ctx context.Context, tx pgx.Tx, query string) (err error) {
		rows, err := tx.Query(ctx, query, ds)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			i := len(*out)
			*out = (*out)[:i+1]
			if err := rows.Scan(&(*out)[i]); err != nil {
				return err
			}
		}
		return rows.Err()
	}
}

func layerCleanup(ctx context.Context, tx pgx.Tx, query string) (err error) {
	tag, err := tx.Exec(ctx, query)
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Int64("count", tag.RowsAffected()).
		Msg("deleted layers")
	return nil
}
