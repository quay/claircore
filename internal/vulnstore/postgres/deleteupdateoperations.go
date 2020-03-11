package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"
)

// DeleteUpdaterOperations removes an UpdateOperation from the vulnstore.
func deleteUpdateOperations(ctx context.Context, pool *pgxpool.Pool, ref ...uuid.UUID) error {
	const query = `DELETE FROM update_operation WHERE ref = ANY($1::uuid[]);`
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/deleteUpdateOperations").
		Logger()
	ctx = log.WithContext(ctx)
	if len(ref) == 0 {
		return nil
	}

	// Pgx seems unwilling to do the []uuid.UUID → uuid[] conversion, so we're
	// forced to make some garbage here.
	refStr := make([]string, len(ref))
	for i := range ref {
		refStr[i] = ref[i].String()
	}
	tag, err := pool.Exec(ctx, query, refStr)
	if err != nil {
		return fmt.Errorf("failed to delete: %w", err)
	}
	if tag.RowsAffected() <= 0 {
		log.Warn().Msg("delete operation deleted no rows")
	}
	return nil
}
