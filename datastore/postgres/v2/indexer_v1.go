package postgres

import (
	"context"
	"fmt"
	"runtime"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/indexer"
)

// NewIndexerV1 returns a configured [IndexerV1].
//
// The passed [pgxpool.Config] will have its tracing and lifecycle hooks
// overwritten.
//
// Values that can be used as IndexerOptions:
//   - [WithMigrations]
//   - [WithMinimumMigration]
func NewIndexerV1(ctx context.Context, cfg *pgxpool.Config, opt ...IndexerOption) (*IndexerV1, error) {
	const prefix = `indexer`
	idxCfg := newIndexerConfig()
	for _, o := range opt {
		idxCfg = o.indexerConfig(idxCfg)
	}

	if idxCfg.Migrations {
		cfg := cfg.ConnConfig.Copy()
		cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
		err := func() error {
			db := stdlib.OpenDB(*cfg)
			defer db.Close()
			migrator := migrate.NewPostgresMigrator(db)
			migrator.Table = migrations.IndexerMigrationTable
			err := migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
			if err != nil {
				return fmt.Errorf("failed to perform migrations: %w", err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	var s IndexerV1
	var err error
	if err = s.init(ctx, cfg, prefix); err != nil {
		return nil, err
	}

	if err := s.checkRevision(ctx, pgx.Identifier([]string{migrations.IndexerMigrationTable}), idxCfg.MinMigration); err != nil {
		return nil, err
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&s, func(s *IndexerV1) {
		panic(fmt.Sprintf("%s:%d: IndexerV1 not closed", file, line))
	})

	return &s, nil
}

// IndexerOption is an option for configuring an indexer datastore.
type IndexerOption interface {
	indexerConfig(indexerConfig) indexerConfig
}

// IndexerConfig is the actual configuration structure used in [NewIndexerV1].
type indexerConfig struct {
	Migrations   bool
	MinMigration int
}

func newIndexerConfig() indexerConfig {
	return indexerConfig{
		Migrations:   false,
		MinMigration: MinimumIndexerMigration,
	}
}

// Static assertion for the [indexer.Store] interface.
var _ indexer.Store = (*IndexerV1)(nil)

// IndexerV1 implements [indexer.Store] backed by a PostgreSQL database.
type IndexerV1 struct {
	storeCommon
}

// Close implements [indexer.Store].
func (s *IndexerV1) Close(_ context.Context) error {
	runtime.SetFinalizer(s, nil)
	return s.storeCommon.Close()
}

// RegisterScanners is a bad name.
func (s *IndexerV1) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	rvs := rotateVersionedScanners(vs)

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `register`, func(ctx context.Context, c *pgxpool.Conn, query string) (err error) {
		_, err = c.Exec(ctx, query, rvs.Name, rvs.Version, rvs.Kind)
		return err
	}))
	if err != nil {
		return err
	}
	return nil
}
