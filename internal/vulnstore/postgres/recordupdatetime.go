package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

// recordUpdaterUpdateTime records that an updater is up to date with vulnerabilities at this time
// inserts an updater with last update timestamp, or updates an existing updater with a new update time
func recordUpdaterUpdateTime(ctx context.Context, pool *pgxpool.Pool, updaterName string, updateTime time.Time) error {
	const (
		// upsert inserts or updates a record of the last time an updater was checked for new vulns
		upsert = `INSERT INTO update_time (
			updater_name,
			last_update_time
		) VALUES (
			$1,
			$2
		)
		ON CONFLICT (updater_name) DO UPDATE
		SET last_update_time = $2
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

	if err := pool.QueryRow(ctx, upsert, updaterName, updateTime).Scan(&returnedUpdaterName); err != nil {
		return fmt.Errorf("failed to upsert last update time: %w", err)
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
		update = `UPDATE update_time
		SET last_update_time = $1
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
