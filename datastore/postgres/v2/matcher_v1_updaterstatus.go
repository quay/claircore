package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

// RecordUpdaterStatus records that an updater is up to date with vulnerabilities at this time
func (s *MatcherV1) RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	failure := !errors.Is(updaterError, nil)
	zlog.Debug(ctx).
		Str("updater", updaterName).
		Bool("failure", failure).
		Msg("start recording update")
	var returnedUpdaterName string
	defer func() {
		zlog.Debug(ctx).
			Str("updater", returnedUpdaterName).
			Msg("done recording update")
	}()

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `RecordUpdaterStatus`, func(ctx context.Context, tx pgx.Tx) (err error) {
		// TODO(hank) Consolidate these queries. There's no real reason they
		// need to be separated.
		if failure {
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `failure`, func(ctx context.Context, tx pgx.Tx, query string) error {
				return tx.QueryRow(ctx, query, updaterName, updateTime, fingerprint, updaterError.Error()).Scan(&returnedUpdaterName)
			}))
		} else {
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `success`, func(ctx context.Context, tx pgx.Tx, query string) error {
				return tx.QueryRow(ctx, query, updaterName, updateTime, fingerprint).Scan(&returnedUpdaterName)
			}))
		}
		return err
	}))
	if err != nil {
		return err
	}

	return nil
}

// RecordUpdaterSetStatus records that all updaters from a updater set are up to
// date with vulnerabilities at this time.
func (s *MatcherV1) RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	err = pgx.BeginFunc(ctx, s.pool, s.call(ctx, `update`, func(ctx context.Context, tx pgx.Tx, query string) error {
		_, err = tx.Exec(ctx, query, updateTime, updaterSet)
		return err
	}))
	if err != nil {
		return err
	}

	return nil
}
