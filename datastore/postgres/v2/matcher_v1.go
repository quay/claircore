package postgres

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/datastore/postgres/migrations"
)

// NewMatcherV1 returns a configured [MatcherV1].
//
// The passed [pgxpool.Config] will have its tracing and lifecycle hooks
// overwritten.
//
// Values that can be used as MatcherOptions:
//   - [WithMigrations]
//   - [WithMinimumMigration]
func NewMatcherV1(ctx context.Context, cfg *pgxpool.Config, opt ...MatcherOption) (*MatcherV1, error) {
	const prefix = `matcher`
	var mCfg matcherConfig
	for _, o := range opt {
		mCfg = o.matcherConfig(mCfg)
	}

	if mCfg.Migrations {
		cfg := cfg.ConnConfig.Copy()
		cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
		err := func() error {
			db := stdlib.OpenDB(*cfg)
			defer db.Close()
			migrator := migrate.NewPostgresMigrator(db)
			migrator.Table = migrations.MatcherMigrationTable
			err := migrator.Exec(migrate.Up, migrations.MatcherMigrations...)
			if err != nil {
				return fmt.Errorf("failed to perform migrations: %w", err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	var s MatcherV1
	if err := s.init(ctx, cfg, prefix); err != nil {
		return nil, err

	}

	if err := s.checkRevision(ctx, pgx.Identifier([]string{migrations.MatcherMigrationTable}), mCfg.MinMigration); err != nil {
		return nil, err
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&s, func(s *MatcherV1) {
		panic(fmt.Sprintf("%s:%d: MatcherV1 not closed", file, line))
	})

	return &s, nil
}

type MatcherOption interface {
	matcherConfig(matcherConfig) matcherConfig
}

type matcherConfig struct {
	Migrations   bool
	MinMigration int
}

func newMatcherConfig() matcherConfig {
	return matcherConfig{
		Migrations:   false,
		MinMigration: MinimumMatcherMigration,
	}
}

// MatcherV1 implements all the relevant interfaces in the datastore package
type MatcherV1 struct {
	storeCommon
	// Initialized is used as an atomic bool for tracking initialization.
	initialized uint32
}

var _ datastore.MatcherV1 = (*MatcherV1)(nil)

// DeleteUpdateOperations implements [datastore.MatcherV1Updater].
func (s *MatcherV1) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) (int64, error) {
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

// Initialized implements [datastore.MatcherV1].
func (s *MatcherV1) Initialized(ctx context.Context) (ok bool, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	span := trace.SpanFromContext(ctx)
	ok = atomic.LoadUint32(&s.initialized) != 0
	span.AddEvent(`loaded`, trace.WithAttributes(attribute.Bool("value", ok)))
	if ok {
		return true, nil
	}

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `initialized`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		return c.QueryRow(ctx, query).Scan(&ok)
	}))
	if err != nil {
		return false, err
	}

	span.AddEvent(`initialized`, trace.WithAttributes(attribute.Bool("value", ok)))
	// There were no rows when we looked, so report that. Don't update the bool,
	// because it's in the 'false' state or another goroutine has read from the
	// database and will want to swap in 'true'.
	if !ok {
		return false, nil
	}
	// If this fails, it means a concurrent goroutine already swapped. Any
	// subsequent calls will see the 'true' value.
	atomic.CompareAndSwapUint32(&s.initialized, 0, 1)
	return true, nil
}

func (s *MatcherV1) Close() error {
	runtime.SetFinalizer(s, nil)
	return s.storeCommon.Close()
}
