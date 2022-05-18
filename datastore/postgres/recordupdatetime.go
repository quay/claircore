package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

// recordUpdaterStatus records that an updater is up to date with vulnerabilities at this time
// inserts an updater with last update timestamp, or updates an existing updater with a new update time
func recordUpdaterStatus(ctx context.Context, pool *pgxpool.Pool, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error {
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

	ctx = zlog.ContextWithValues(ctx,
		"component", "internal/vulnstore/postgres/recordUpdaterStatus")

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var returnedUpdaterName string

	if updaterError == nil {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("recording successful update")
		_, err := pool.Exec(ctx, upsertSuccessfulUpdate, updaterName, updateTime, fingerprint)
		if err != nil {
			return fmt.Errorf("failed to upsert successful updater status: %w", err)
		}
	} else {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("recording failed update")
		if err := pool.QueryRow(ctx, upsertFailedUpdate, updaterName, updateTime, fingerprint, updaterError.Error()).Scan(&returnedUpdaterName); err != nil {
			return fmt.Errorf("failed to upsert failed updater status: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	zlog.Debug(ctx).
		Str("updater", updaterName).
		Msg("updater status stored in database")

	return nil
}

// recordUpdaterSetStatus records that all updaters for a single updater set are up to date with vulnerabilities at this time
// updates all existing updaters from this updater set with the new update time
// the updater set parameter passed needs to match the prefix of the given updater set name format
func recordUpdaterSetStatus(ctx context.Context, pool *pgxpool.Pool, updaterSet string, updateTime time.Time) error {
	const (
		update = `UPDATE updater_status
		SET last_attempt = $1,
			last_success = $1,
			last_run_succeeded = 'true'
		WHERE updater_name like $2 || '%';`
	)

	ctx = zlog.ContextWithValues(ctx,
		"component", "internal/vulnstore/postgres/recordUpdaterSetStatus")

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := pool.Exec(ctx, update, updateTime, updaterSet)
	if err != nil {
		return fmt.Errorf("failed to update updater statuses for updater set %s: %w", updaterSet, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	zlog.Debug(ctx).
		Str("factory", updaterSet).
		Int64("rowsAffected", tag.RowsAffected()).
		Msg("status updated for factory updaters")

	return nil
}
