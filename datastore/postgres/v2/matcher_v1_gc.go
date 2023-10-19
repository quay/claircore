package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GCThrottle sets a limit for the number of deleted update operations (and
// subsequent cascade deletes in the uo_vuln table) that can occur in a GC run.
const GCThrottle = 50

// GC performs garbage collection on tables in the Matcher store.
//
// GC is split into two phases, first it will identify any update operations
// which are older then the provided keep value and delete these.
//
// Next it will perform updater-based deletions of any vulnerabilities from the
// vuln table which are not longer referenced by update operations.
//
// The GC is throttled to not overload the database with CASCADE deletes. If a
// full GC is required, run this method until the returned value is 0.
func (s *MatcherV1) GC(ctx context.Context, keep int) (_ int64, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	var (
		total   int64
		deleted int64
	)

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `GC`, func(ctx context.Context, tx pgx.Tx) error {
		var ops []uuid.UUID
		span := trace.SpanFromContext(ctx)

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `eligible`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			rows, err := tx.Query(ctx, query, keep+1, keep)
			if err != nil {
				return err
			}
			tmp, err := pgx.CollectRows(rows, pgx.RowTo[[]uuid.UUID])
			if err != nil {
				return err
			}
			for _, t := range tmp {
				ops = append(ops, t...)
			}
			return nil
		}))
		if err != nil {
			return err
		}

		total = int64(len(ops))
		switch {
		case len(ops) > GCThrottle:
			ops = ops[:GCThrottle]
		case len(ops) == 0:
			return nil
		}
		span.SetAttributes(attribute.Int64("total", total), attribute.Int("ops", len(ops)))

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `delete_ops`, func(ctx context.Context, tx pgx.Tx, query string) error {
			tag, err := s.pool.Exec(ctx, query, ops)
			deleted = tag.RowsAffected()
			return err
		}))
		if err != nil {
			return err
		}

		var updaters []string
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `distinct`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			rows, err := tx.Query(ctx, query)
			if err != nil {
				return err
			}
			updaters, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		}))
		if err != nil {
			return err
		}

		for _, u := range updaters {
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `orphaned`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
				ctx = zlog.ContextWithValues(ctx, "updater", u)
				trace.SpanFromContext(ctx).SetAttributes(attribute.String("updater", u))
				zlog.Debug(ctx).
					Msg("clean up start")
				zlog.Debug(ctx).Msg("clean up done")

				_, err = tx.Exec(ctx, query, u)
				return err
			}))
			if err != nil {
				return err
			}
		}

		return nil
	}))
	if err != nil {
		return 0, err
	}

	return total - deleted, nil
}
