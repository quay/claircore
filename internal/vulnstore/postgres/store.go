package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	db *sqlx.DB
	// lower level access to the conn pool
	pool *pgxpool.Pool
}

func NewVulnStore(db *sqlx.DB, pool *pgxpool.Pool) *Store {
	return &Store{
		db:   db,
		pool: pool,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// UpdateVulnerabilities implements driver.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// GetUpdateOperations implements driver.Updater.
func (s *Store) GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error) {
	return getUpdateOperations(ctx, s.pool, updater...)
}

// DeleteUpdateOperations implements driver.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) error {
	return deleteUpdateOperations(ctx, s.pool, id...)
}

// GetUpdateOperationDiff implements driver.Updater.
func (s *Store) GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}

// vulnstore.Vulnerability interface methods //

func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, nil
}
