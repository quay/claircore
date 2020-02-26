package postgres

import (
	"context"
	"fmt"

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

// vulnstore.Updater interface methods //

func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error {
	err := updateVulnerabilites(ctx, s.pool, updater, UOID, fingerprint, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %w", err)
	}
	return nil
}

func (s *Store) GetUpdateOperations(ctx context.Context, updaters []string) (map[string][]*driver.UpdateOperation, error) {
	UOs, err := getUpdateOperations(ctx, s.pool, updaters)
	if err != nil {
		return nil, fmt.Errorf("failed to get update operations for %+v: %w", updaters, err)
	}
	return UOs, nil
}

func (s *Store) DeleteUpdateOperations(ctx context.Context, UOIDs []string) error {
	err := deleteUpdateOperations(ctx, s.pool, UOIDs)
	if err != nil {
		return fmt.Errorf("failed to delete UOIDS %v: %w", UOIDs, err)
	}
	return nil
}

func (s *Store) GetUpdateOperationDiff(ctx context.Context, UOID_A, UOID_B string) (*driver.UpdateDiff, error) {
	diff, err := getUpdateOperationDiff(ctx, s.pool, UOID_A, UOID_B)
	if err != nil {
		return nil, fmt.Errorf("failed to generate diff for %v %v: %v", UOID_A, UOID_B, err)
	}
	return diff, nil
}

// vulnstore.Vulnerability interface methods //

func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, nil
}
