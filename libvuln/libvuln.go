package libvuln

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/matchers"
	"github.com/quay/claircore/pkg/ctxlock"
)

// Libvuln exports methods for scanning an IndexReport and created
// a VulnerabilityReport.
//
// Libvuln also runs background updaters which keep the vulnerability
// database consistent.
type Libvuln struct {
	store           vulnstore.Store
	pool            *pgxpool.Pool
	locks           *ctxlock.Locker
	matchers        []driver.Matcher
	enrichers       []driver.Enricher
	updateRetention int
	updaters        *updates.Manager
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Opts) (*Libvuln, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/New"))

	err := opts.parse(ctx)
	if err != nil {
		return nil, err
	}

	zlog.Info(ctx).
		Int32("count", opts.MaxConnPool).
		Msg("initializing store")
	if err := opts.migrations(ctx); err != nil {
		return nil, err
	}
	pool, err := opts.pool(ctx)
	if err != nil {
		return nil, err
	}

	l := &Libvuln{
		store:           postgres.NewVulnStore(pool),
		pool:            pool,
		updateRetention: opts.UpdateRetention,
		enrichers:       opts.Enrichers,
	}

	// create matchers based on the provided config.
	l.matchers, err = matchers.NewMatchers(ctx,
		opts.Client,
		matchers.WithEnabled(opts.MatcherNames),
		matchers.WithConfigs(opts.MatcherConfigs),
		matchers.WithOutOfTree(opts.Matchers),
	)
	zlog.Info(ctx).Int("len", len(l.matchers)).Msg("matchers created")
	if err != nil {
		return nil, err
	}

	// create update manager
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		return nil, err
	}
	l.updaters, err = updates.NewManager(ctx,
		l.store,
		locks,
		opts.Client,
		updates.WithBatchSize(opts.UpdateWorkers),
		updates.WithInterval(opts.UpdateInterval),
		updates.WithEnabled(opts.UpdaterSets),
		updates.WithConfigs(opts.UpdaterConfigs),
		updates.WithOutOfTree(opts.Updaters),
		updates.WithGC(opts.UpdateRetention),
	)
	if err != nil {
		return nil, err
	}

	// launch background updater
	if !opts.DisableBackgroundUpdates {
		go l.updaters.Start(ctx)
	}
	zlog.Info(ctx).Msg("libvuln initialized")
	return l, nil
}

func (l *Libvuln) Close(ctx context.Context) error {
	l.locks.Close(ctx)
	l.pool.Close()
	return nil
}

// FetchUpdates runs configured updaters.
func (l *Libvuln) FetchUpdates(ctx context.Context) error {
	return l.updaters.Run(ctx)
}

// Scan creates a VulnerabilityReport given a manifest's IndexReport.
func (l *Libvuln) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	if s, ok := l.store.(matcher.Store); ok {
		return matcher.EnrichedMatch(ctx, ir, l.matchers, l.enrichers, s)
	}
	return matcher.Match(ctx, ir, l.matchers, l.store)
}

// UpdateOperations returns UpdateOperations in date descending order keyed by the
// Updater name
func (l *Libvuln) UpdateOperations(ctx context.Context, kind driver.UpdateKind, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	return l.store.GetUpdateOperations(ctx, kind, updaters...)
}

// DeleteUpdateOperations removes UpdateOperations.
// A call to GC or GCFull must be run after this to garbage collect vulnerabilities associated
// with the UpdateOperation.
//
// The number of UpdateOperations deleted is returned.
func (l *Libvuln) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) (int64, error) {
	return l.store.DeleteUpdateOperations(ctx, ref...)
}

// UpdateDiff returns an UpdateDiff describing the changes between prev
// and cur.
func (l *Libvuln) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return l.store.GetUpdateDiff(ctx, prev, cur)
}

// LatestUpdateOperations returns references for the latest update for every
// known updater.
//
// These references are okay to expose externally.
func (l *Libvuln) LatestUpdateOperations(ctx context.Context, kind driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	return l.store.GetLatestUpdateRefs(ctx, kind)
}

// LatestUpdateOperation returns a reference to the latest known update.
//
// This can be used by clients to determine if a call to Scan is likely to
// return new results.
func (l *Libvuln) LatestUpdateOperation(ctx context.Context, kind driver.UpdateKind) (uuid.UUID, error) {
	return l.store.GetLatestUpdateRef(ctx, kind)
}

// GC will cleanup any update operations older then the configured UpdatesRetention value.
// GC is throttled and ensure its a good citizen to the database.
//
// The returned int is the number of outstanding UpdateOperations not deleted due to throttling.
// To run GC to completion use the GCFull method.
func (l *Libvuln) GC(ctx context.Context) (int64, error) {
	if l.updateRetention == 0 {
		return 0, fmt.Errorf("gc is disabled")
	}
	return l.store.GC(ctx, l.updateRetention)
}

// GCFull will run garbage collection until all expired update operations
// and stale vulnerabilites are removed in accordance with the UpdateRetention
// value.
//
// GCFull may return an error accompanied by its other return value,
// the number of oustanding update operations not deleted.
func (l *Libvuln) GCFull(ctx context.Context) (int64, error) {
	if l.updateRetention == 0 {
		return 0, fmt.Errorf("gc is disabled")
	}
	i, err := l.store.GC(ctx, l.updateRetention)
	if err != nil {
		return i, err
	}

	for i > 0 {
		i, err = l.store.GC(ctx, l.updateRetention)
		if err != nil {
			return i, err
		}
	}

	return i, err
}

// Initialized reports whether the backing vulnerability store is initialized.
func (l *Libvuln) Initialized(ctx context.Context) (bool, error) {
	return l.store.Initialized(ctx)
}
