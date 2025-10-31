package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore/libvuln/driver"
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
	log := slog.With("updater", updaterName)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var returnedUpdaterName string

	if updaterError == nil {
		log.DebugContext(ctx, "recording successful update")
		_, err := tx.Exec(ctx, upsertSuccessfulUpdate, updaterName, updateTime, fingerprint)
		if err != nil {
			return fmt.Errorf("failed to upsert successful updater status: %w", err)
		}
	} else {
		log.DebugContext(ctx, "recording failed update")
		if err := tx.QueryRow(ctx, upsertFailedUpdate, updaterName, updateTime, fingerprint, updaterError.Error()).Scan(&returnedUpdaterName); err != nil {
			return fmt.Errorf("failed to upsert failed updater status: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	log.DebugContext(ctx, "updater status stored in database")

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

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, update, updateTime, updaterSet)
	if err != nil {
		return fmt.Errorf("failed to update updater statuses for updater set %s: %w", updaterSet, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	slog.DebugContext(ctx, "status updated for factory updaters",
		"factory", updaterSet,
		"rowsAffected", tag.RowsAffected())

	return nil
}
