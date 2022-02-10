package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

// recordUpdaterUpdateTime records that an updater is up to date with vulnerabilities at this time
// inserts an updater with last update timestamp, or updates an existing updater with a new update time
func recordUpdaterUpdateTime(ctx context.Context, pool *pgxpool.Pool, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error {
	const (
		// upsertSuccessfulUpdate inserts or updates a record of the last time an updater successfully checked for new vulns
		upsertSuccessfulUpdate = `INSERT INTO updater_status (
			updater_name,
			last_attempt,
			last_success,
			last_run_succeeded,
			last_attempt_fingerprint
		) VALUES (
			$1,
			$2,
			$2,
			'true',
			$3
		)
		ON CONFLICT (updater_name) DO UPDATE
		SET last_attempt = $2,
			last_success = $2,
			last_run_succeeded = 'true',
			last_attempt_fingerprint = $3
		RETURNING updater_name;`

		// upsertFailedUpdate inserts or updates a record of the last time an updater attempted but failed to check for new vulns
		upsertFailedUpdate = `INSERT INTO updater_status (
					updater_name,
					last_attempt,
					last_run_succeeded,
					last_attempt_fingerprint,
					last_error
				) VALUES (
					$1,
					$2,
					'false',
					$3,
					$4
				)
				ON CONFLICT (updater_name) DO UPDATE
				SET last_attempt = $2,
					last_run_succeeded = 'false',
					last_attempt_fingerprint = $3,
					last_error = $4
				RETURNING updater_name;`
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordUpdaterUpdateTime"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var returnedUpdaterName string

	if updaterError == nil {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("debug: using upsertSuccessfulUpdate")
		fmt.Printf("debug: using upsertSuccessfulUpdate")
		if err := pool.QueryRow(ctx, upsertSuccessfulUpdate, updaterName, updateTime, fingerprint).Scan(&returnedUpdaterName); err != nil {
			return fmt.Errorf("failed to upsert last update time: %w", err)
		}
	} else {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("debug: using upsertFailedUpdate")
		fmt.Printf("debug: using upsertFailedUpdate")
		if err := pool.QueryRow(ctx, upsertFailedUpdate, updaterName, updateTime, fingerprint, updaterError.Error()).Scan(&returnedUpdaterName); err != nil {
			return fmt.Errorf("failed to upsert last update time: %w", err)
		}
	}

	zlog.Debug(ctx).
		Str("updater", updaterName).
		Msg("Updater last update time stored in database")

	return nil
}

// recordUpdaterSetUpdateTime records that all updaters for a single updaterSet are up to date with vulnerabilities at this time
// updates all existing updaters from this upater set with the new update time
// the updater set parameteer passed needs to match the prefix of the given udpdater set name format
func recordUpdaterSetUpdateTime(ctx context.Context, pool *pgxpool.Pool, updaterSet string, updateTime time.Time) error {
	const (
		update = `UPDATE updater_status
		SET last_attempt = $1,
			last_success = $1,
			last_run_succeeded = 'true'
		WHERE updater_name like $2 || '%'
		RETURNING updater_name;`
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordUpdaterSetUpdateTime"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var updaterName string

	if err := pool.QueryRow(ctx, update, updateTime, updaterSet).Scan(&updaterName); err != nil {
		return fmt.Errorf("failed to update all last update times for updater set %s: %w", updaterSet, err)
	}

	zlog.Debug(ctx).
		Str("updaterSet", updaterSet).
		Msg(fmt.Sprintf("Last update time stored in database for all %s updaters", updaterSet))

	return nil
}
