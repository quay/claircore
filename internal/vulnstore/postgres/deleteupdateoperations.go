package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"
)

const (
	deleteUpdateOperation = `DELETE FROM update_operation WHERE ref IN $1::uuid[];`
)

// DeleteUpdaterOperations removes an UpdateOperation from the vulnstore.
func deleteUpdateOperations(ctx context.Context, pool *pgxpool.Pool, ref ...uuid.UUID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/deleteUpdateOperations").
		Logger()
	ctx = log.WithContext(ctx)
	if len(ref) == 0 {
		return nil
	}

	tag, err := pool.Exec(ctx, deleteUpdateOperation, ref)
	if err != nil {
		return fmt.Errorf("failed to delete: %w", err)
	}
	if tag.RowsAffected() <= 0 {
		log.Warn().Msg("delete operation deleted no rows")
	}
	return nil
}
