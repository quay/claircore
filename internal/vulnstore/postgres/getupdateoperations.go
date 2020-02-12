package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
)

const (
	selectUpdateOperationsByUpdater = `SELECT ref, updater, fingerprint, date
	FROM update_operation WHERE updater = $1 ORDER BY id DESC;`
	selectDistinctUpdaters = `SELECT DISTINCT(updater) FROM update_operation;`
)

func getUpdateOperations(ctx context.Context, pool *pgxpool.Pool, updater ...string) (map[string][]driver.UpdateOperation, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/getUpdateOperations").
		Logger()
	ctx = log.WithContext(ctx)

	tx, err := pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to being transaction: %w", err)
	}
	out := make(map[string][]driver.UpdateOperation)

	// Get distinct updaters from database if nothing specified.
	if len(updater) == 0 {
		updater = []string{}
		rows, err := tx.Query(ctx, selectDistinctUpdaters)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			rows.Close()
		default:
			rows.Close()
			return nil, fmt.Errorf("failed to get distinct updates: %w", err)
		}
		// use a closure to defer rows.Close() and ensure connection can be re-used
		// see: https://pkg.go.dev/github.com/jackc/pgx?tab=doc#Rows
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				var u string
				err := rows.Scan(&u)
				if err != nil {
					return fmt.Errorf("failed to scan updater: %w", err)
				}
				updater = append(updater, u)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	for _, u := range updater {
		// use a closure to defer rows.Close() and ensure connection can be re-used
		// see: https://pkg.go.dev/github.com/jackc/pgx?tab=doc#Rows
		err := func() error {
			rows, err := tx.Query(ctx, selectUpdateOperationsByUpdater, u)
			if rows != nil {
				defer rows.Close()
			}
			switch {
			case err == nil:
			case errors.Is(err, pgx.ErrNoRows):
				log.Warn().Str("updater", u).Msg("no update operations for this updater")
				return nil
			default:
				return fmt.Errorf("failed to retrieve update operation for updater %v: %w", updater, err)
			}
			ops := []driver.UpdateOperation{}
			for rows.Next() {
				ops = append(ops, driver.UpdateOperation{})
				uo := &ops[len(ops)-1]
				err := rows.Scan(
					&uo.Ref,
					&uo.Updater,
					&uo.Fingerprint,
					&uo.Date,
				)
				if err != nil {
					return fmt.Errorf("failed to scan update operation for updater %q: %w", u, err)
				}
			}
			out[u] = ops
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return out, nil
}
