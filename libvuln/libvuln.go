package libvuln

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/matchers"
)

// Libvuln exports methods for scanning an IndexReport and created
// a VulnerabilityReport.
//
// Libvuln also runs background updaters which keep the vulnerability
// database consistent.
type Libvuln struct {
	store           datastore.MatcherStore
	locker          LockSource
	pool            *pgxpool.Pool
	matchers        []driver.Matcher
	enrichers       []driver.Enricher
	updateRetention int
	updaters        *updates.Manager
}

// TODO (crozzy): Find a home for this and stop redefining it.
// LockSource abstracts over how locks are implemented.
//
// An online system needs distributed locks, offline use cases can use
// process-local locks.
type LockSource interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
	Close(context.Context) error
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Options) (*Libvuln, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/New")

	// required
	if opts.Store == nil {
		return nil, fmt.Errorf("field Store cannot be nil")
	}
	if opts.UpdateRetention == 1 || opts.UpdateRetention < 0 {
		return nil, fmt.Errorf("update retention must be 0 or greater then 1")
	}

	// optional
	if opts.UpdateInterval == 0 || opts.UpdateInterval < time.Minute {
		opts.UpdateInterval = DefaultUpdateInterval
	}
	// This gives us a ±60 second range, rounded to the nearest tenth of a
	// second.
	const jitter = 120000
	ms := time.Duration(rand.Intn(jitter)-(jitter/2)) * time.Microsecond
	ms = ms.Round(100 * time.Millisecond)
	opts.UpdateInterval += ms

	if opts.UpdateWorkers <= 0 {
		opts.UpdateWorkers = DefaultUpdateWorkers
	}

	if opts.Client == nil {
		zlog.Warn(ctx).
			Msg("using default HTTP client; this will become an error in the future")
		opts.Client = http.DefaultClient // TODO(hank) Remove DefaultClient
	}
	if opts.UpdaterConfigs == nil {
		opts.UpdaterConfigs = make(map[string]driver.ConfigUnmarshaler)
	}

	l := &Libvuln{
		store:           opts.Store,
		locker:          opts.Locker,
		updateRetention: opts.UpdateRetention,
		enrichers:       opts.Enrichers,
	}

	// create matchers based on the provided config.
	var err error
	l.matchers, err = matchers.NewMatchers(ctx,
		opts.Client,
		matchers.WithEnabled(opts.MatcherNames),
		matchers.WithConfigs(opts.MatcherConfigs),
		matchers.WithOutOfTree(opts.Matchers),
	)
	if err != nil {
		return nil, err
	}

	zlog.Info(ctx).Array("matchers", matcherLog(l.matchers)).Msg("matchers created")

	l.updaters, err = updates.NewManager(ctx,
		l.store,
		l.locker,
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
	l.locker.Close(ctx)
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

// Matcherlog is a logging helper. It prints the name of every matcher and a
// generated documentation URL.
type matcherLog []driver.Matcher

func (l matcherLog) MarshalZerologArray(a *zerolog.Array) {
	for _, m := range l {
		t := reflect.ValueOf(m).Elem().Type()
		a.Dict(zerolog.Dict().
			Str("name", m.Name()).
			Str("docs", `https://pkg.go.dev/`+t.PkgPath()))
	}
}
