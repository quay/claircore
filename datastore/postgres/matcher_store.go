package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/libvuln/driver"
)

// InitPostgresMatcherStore initialize a indexer.Store given libindex.Opts
func InitPostgresMatcherStore(_ context.Context, pool *pgxpool.Pool, doMigration bool) (datastore.MatcherStore, error) {
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer db.Close()

	// do migrations if requested
	if doMigration {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.MatcherMigrationTable
		err := migrator.Exec(migrate.Up, migrations.MatcherMigrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := NewMatcherStore(pool)
	return store, nil
}

// MatcherStore implements all interfaces in the vulnstore package
type MatcherStore struct {
	pool *pgxpool.Pool
	// Initialized is used as an atomic bool for tracking initialization.
	initialized uint32
}

func NewMatcherStore(pool *pgxpool.Pool) *MatcherStore {
	return &MatcherStore{
		pool: pool,
	}
}

var (
	_ datastore.Updater       = (*MatcherStore)(nil)
	_ datastore.Vulnerability = (*MatcherStore)(nil)
)

// UpdateVulnerabilities implements vulnstore.Updater.
func (s *MatcherStore) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *MatcherStore) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) (int64, error) {
	const query = `DELETE FROM update_operation WHERE ref = ANY($1::uuid[]);`
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/deleteUpdateOperations")
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

// RecordUpdaterStatus records that an updater is up to date with vulnerabilities at this time
func (s *MatcherStore) RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error {
	return recordUpdaterStatus(ctx, s.pool, updaterName, updateTime, fingerprint, updaterError)
}

// RecordUpdaterSetStatus records that all updaters from a updater set are up to date with vulnerabilities at this time
func (s *MatcherStore) RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) error {
	return recordUpdaterSetStatus(ctx, s.pool, updaterSet, updateTime)
}
