package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
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

func (s *Store) PutHash(updater string, hash string) error {
	err := putHash(s.db, updater, hash)
	if err != nil {
		return fmt.Errorf("failed to put hash: %v", err)
	}
	return nil
}

func (s *Store) GetHash(ctx context.Context, updater string) (string, error) {
	v, err := getHash(ctx, s.db, updater)
	if err != nil {
		return "", fmt.Errorf("failed to get hash: %v", err)
	}
	return v, nil
}

func (s *Store) PutVulnerabilities(ctx context.Context, updater string, hash string, vulns []*claircore.Vulnerability) error {
	err := putVulnerabilities(ctx, s.pool, updater, hash, vulns)
	if err != nil {
		return fmt.Errorf("failed to put vulnerabilities: %v", err)
	}
	return nil
}

// vulnstore.Vulnerability interface methods //

func (s *Store) Get(ctx context.Context, records []*claircore.ScanRecord, opts vulnstore.GetOpts) (map[int][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, nil
}
