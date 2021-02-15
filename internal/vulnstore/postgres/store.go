package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	pool *pgxpool.Pool
	// Initialized is used as an atomic bool for tracking initialization.
	initialized uint32
}

func NewVulnStore(pool *pgxpool.Pool) *Store {
	return &Store{
		pool: pool,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// UpdateVulnerabilities implements vulnstore.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// GetUpdateOperations implements vulnstore.Updater.
func (s *Store) GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error) {
	return getUpdateOperations(ctx, s.pool, updater...)
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) (int64, error) {
	const query = `DELETE FROM update_operation WHERE ref = ANY($1::uuid[]);`
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/deleteUpdateOperations"))
	if len(id) == 0 {
		return 0, nil
	}

	// Pgx seems unwilling to do the []uuid.UUID → uuid[] conversion, so we're
	// forced to make some garbage here.
	refStr := make([]string, len(id))
	for i := range id {
		refStr[i] = id[i].String()
	}
	tag, err := s.pool.Exec(ctx, query, refStr)
	if err != nil {
		return 0, fmt.Errorf("failed to delete: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetUpdateOperationDiff implements vulnstore.Updater.
func (s *Store) GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}
func (s *Store) GetUpdateDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}

func (s *Store) GetLatestUpdateRefs(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return getLatestRefs(ctx, s.pool)
}

// Get implements vulnstore.Vulnerability.
func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %v", err)
	}
	return vulns, nil
}
