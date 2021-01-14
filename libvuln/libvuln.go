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
)

// Libvuln exports methods for scanning an IndexReport and created
// a VulnerabilityReport.
//
// Libvuln also runs background updaters which keep the vulnerability
// database consistent.
type Libvuln struct {
	store           vulnstore.Store
	pool            *pgxpool.Pool
	matchers        []driver.Matcher
	updateRetention int
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
		matchers:        opts.Matchers,
		updateRetention: opts.UpdateRetention,
	}

	// create update manager
	updateMgr, err := updates.NewManager(ctx,
		l.store,
		pool,
		opts.Client,
		updates.WithBatchSize(opts.UpdateWorkers),
		updates.WithInterval(opts.UpdateInterval),
		updates.WithEnabled(opts.UpdaterSets),
		updates.WithConfigs(opts.UpdaterConfigs),
		updates.WithOutOfTree(opts.Updaters),
		updates.WithGC(opts.UpdateRetention),
	)

	// perform initial update
	if err := updateMgr.Run(ctx); err != nil {
		zlog.Error(ctx).Err(err).Msg("encountered error while updating")
	}

	// launch background updater
	if !opts.DisableBackgroundUpdates {
		go updateMgr.Start(ctx)
	}
	zlog.Info(ctx).Msg("libvuln initialized")
	return l, nil
}

// Scan creates a VulnerabilityReport given a manifest's IndexReport.
func (l *Libvuln) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	return matcher.Match(ctx, ir, l.matchers, l.store)
}

// UpdateOperations returns UpdateOperations in date descending order keyed by the
// Updater name
func (l *Libvuln) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	return l.store.GetUpdateOperations(ctx, updaters...)
}

// DeleteUpdateOperations removes one or more update operations and their
// associated vulnerabilities from the vulnerability database.
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
func (l *Libvuln) LatestUpdateOperations(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return l.store.GetLatestUpdateRefs(ctx)
}

// LatestUpdateOperation returns a reference to the latest known update.
//
// This can be used by clients to determine if a call to Scan is likely to
// return new results.
func (l *Libvuln) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	return l.store.GetLatestUpdateRef(ctx)
}

// GC will cleanup any update operations older then the configured UpdatesRetention value.
// GC returns
//
// GC is throttled and ensure its a good citizen to the database.
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
// GCFull may return an error accompanied by its other two return values;
// the number of oustanding update operations to remove and the number of
// vulnerabilities deleted.
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
