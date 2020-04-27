package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
)

// GetLatestUpdateRef implements driver.Updater.
func (s *Store) GetLatestUpdateRef(ctx context.Context) (uuid.UUID, error) {
	const query = `SELECT ref FROM update_operation ORDER BY id USING > LIMIT 1;`
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/getLatestRef").
		Logger()
	ctx = log.WithContext(ctx)

	var ref uuid.UUID
	if err := s.pool.QueryRow(ctx, query).Scan(&ref); err != nil {
		return uuid.Nil, err
	}
	return ref, nil
}

func getLatestRefs(ctx context.Context, pool *pgxpool.Pool) (map[string]uuid.UUID, error) {
	const query = `SELECT updater, ref FROM update_operation GROUP BY updater ORDER BY updater, id USING > LIMIT 1;`
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/getLatestRefs").
		Logger()
	ctx = log.WithContext(ctx)

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ret := make(map[string]uuid.UUID)
	var u string
	var id uuid.UUID
	for rows.Next() {
		if err := rows.Scan(&u, &id); err != nil {
			return nil, err
		}
		ret[u] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	log.Debug().
		Int("count", len(ret)).
		Msg("found updaters")
	return ret, nil
}

func getUpdateOperations(ctx context.Context, pool *pgxpool.Pool, updater ...string) (map[string][]driver.UpdateOperation, error) {
	const (
		query       = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = $1 ORDER BY id DESC;`
		getUpdaters = `SELECT DISTINCT(updater) FROM update_operation;`
	)
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/getUpdateOperations").
		Logger()
	ctx = log.WithContext(ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	out := make(map[string][]driver.UpdateOperation)

	// Get distinct updaters from database if nothing specified.
	if len(updater) == 0 {
		updater = []string{}
		rows, err := tx.Query(ctx, getUpdaters)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return nil, nil
		default:
			return nil, fmt.Errorf("failed to get distinct updates: %w", err)
		}
		defer rows.Close() // OK to defer and call, as per docs.
		for rows.Next() {
			var u string
			err := rows.Scan(&u)
			if err != nil {
				return nil, fmt.Errorf("failed to scan updater: %w", err)
			}
			updater = append(updater, u)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows.Close()
	}

	// Take care to close the rows object on every iteration.
	var rows pgx.Rows
	for _, u := range updater {
		rows, err = tx.Query(ctx, query, u)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			log.Warn().Str("updater", u).Msg("no update operations for this updater")
			rows.Close()
			continue
		default:
			rows.Close()
			return nil, fmt.Errorf("failed to retrieve update operation for updater %v: %w", updater, err)
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
				rows.Close()
				return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", u, err)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out[u] = ops
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return out, nil
}
