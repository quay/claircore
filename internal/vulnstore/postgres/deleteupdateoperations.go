package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"
)

const (
	// deleteUpdateOperation deletes an UpdateOperation
	// and CASCADE deletes all associated vulnerabilities.
	deleteUpdateOperation = `
	DELETE FROM update_operation
	WHERE id = $1;
	`
)

// deleteUpdaterOperations removes an UpdateOperation from the vulnstore.
// On UpdateOperation deletion all associated vulnerabilities are CASCADE
// deleted.
func deleteUpdateOperations(ctx context.Context, pool *pgxpool.Pool, UOIDs []string) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/deleteUpdateOperation").
		Logger()
	ctx = log.WithContext(ctx)
	tx, err := pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if len(UOIDs) == 0 {
		log.Warn().Msg("no UOIDs provided")
		return nil
	}

	for _, UOID := range UOIDs {
		tag, err := tx.Exec(ctx, deleteUpdateOperation, UOID)
		if err != nil {
			return fmt.Errorf("failed to delete UOID %v: %w", UOID, err)
		}
		if tag.RowsAffected() <= 0 {
			log.Warn().Str("UOID", UOID).Msg("delete operation deleted no rows")
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit transation: %w", err)
	}
	return nil
}
