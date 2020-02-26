package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/rs/zerolog"
)

const (
	selectUpdateOperationsByUpdater = `
	SELECT id, updater, fingerprint, date
	FROM update_operation 
	WHERE updater = $1 ORDER BY date DESC;
	`
	selectDistinctUpdaters = `
	SELECT DISTINCT(updater) FROM update_operation;
	`
)

func getUpdateOperations(ctx context.Context, pool *pgxpool.Pool, updaters []string) (map[string][]*driver.UpdateOperation, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/getUpdateOperations").
		Logger()
	ctx = log.WithContext(ctx)
	tx, err := pool.Begin(ctx)
	defer tx.Rollback(ctx)
	out := map[string][]*driver.UpdateOperation{}

	// get distinct updaters from database if no updaters provided.
	if updaters == nil || len(updaters) == 0 {
		updaters = []string{}
		rows, err := tx.Query(ctx, selectDistinctUpdaters)
		switch {
		case err == pgx.ErrNoRows:
			rows.Close()
		case err != nil:
			rows.Close()
			return nil, fmt.Errorf("failed to get distinct updates: %w", err)
		default:
			// use a closure to defer rows.Close() and ensure connection can be re-used
			// see: https://pkg.go.dev/github.com/jackc/pgx?tab=doc#Rows
			err := func() error {
				defer rows.Close()
				for rows.Next() {
					var updater string
					err := rows.Scan(&updater)
					if err != nil {
						return fmt.Errorf("failed to scan updater: %w", err)
					}
					updaters = append(updaters, updater)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
		}
	}

	for _, updater := range updaters {
		// use a closure to defer rows.Close() and ensure connection can be re-used
		// see: https://pkg.go.dev/github.com/jackc/pgx?tab=doc#Rows
		err := func() error {
			rows, err := tx.Query(ctx, selectUpdateOperationsByUpdater, updater)
			defer rows.Close()
			switch {
			case err == pgx.ErrNoRows:
				log.Warn().Str("updater", updater).Msg("no update operations for this updater")
			case err != nil:
				return fmt.Errorf("failed to retrieve update operation for updater %v: %w", updater, err)
			default:
				UOs := []*driver.UpdateOperation{}
				for rows.Next() {
					uo := &driver.UpdateOperation{}
					err := rows.Scan(
						&uo.ID,
						&uo.Updater,
						&uo.Fingerprint,
						&uo.Date,
					)
					UOs = append(UOs, uo)
					if err != nil {
						return fmt.Errorf("failed to scan update operation for updater %v: %w", updater, err)
					}
				}
				out[updater] = UOs
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	err = tx.Commit(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to commit transcation: %w", err)
	}
	return out, nil
}
