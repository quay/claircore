package updates

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/updater"
)

const (
	DefaultInterval = time.Duration(30 * time.Minute)
)

var DefaultBatchSize = runtime.GOMAXPROCS(0)

type Configs map[string]driver.ConfigUnmarshaler

// LockSource abstracts over how locks are implemented.
//
// An online system needs distributed locks, offline use cases can use
// process-local locks.
type LockSource interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
}

// Manager oversees the configuration and invocation of vulnstore updaters.
//
// The Manager may be used in a one-shot fashion, configured to run background
// jobs, or both.
type Manager struct {
	// provides run-time updater construction.
	factories map[string]driver.UpdaterSetFactory
	// max in-flight updaters.
	batchSize int
	// update interval used once Manager.Start is invoked, otherwise
	// this field is not used.
	interval time.Duration
	// configs provided to updaters once constructed.
	configs Configs
	// instructs manager to run gc and provides the number of
	// update operations to keep.
	updateRetention int

	locks  LockSource
	client *http.Client
	store  datastore.Updater
}

// NewManager will return a manager ready to have its Start or Run methods called.
func NewManager(ctx context.Context, store datastore.Updater, locks LockSource, client *http.Client, opts ...ManagerOption) (*Manager, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/updates/NewManager")

	// the default Manager
	m := &Manager{
		store:     store,
		locks:     locks,
		factories: updater.Registered(),
		batchSize: runtime.GOMAXPROCS(0),
		interval:  DefaultInterval,
		client:    client,
	}

	// these options can be ran order independent.
	for _, opt := range opts {
		opt(m)
	}

	if m.updateRetention == 1 {
		return nil, errors.New("update retention cannot be 1")
	}

	err := updater.Configure(ctx, m.factories, m.configs, m.client)
	if err != nil {
		return nil, fmt.Errorf("failed to configure updater set factory: %w", err)
	}

	return m, nil
}

// Start will run updaters at the given interval.
//
// Start is designed to be ran as a goroutine. Cancel the provided Context
// to end the updater loop.
//
// Start must only be called once between context cancellations.
func (m *Manager) Start(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/updates/Manager.Start")

	if m.interval == 0 {
		return fmt.Errorf("manager must be configured with an interval to start")
	}

	// perform the initial run
	zlog.Info(ctx).Msg("starting initial updates")
	err := m.Run(ctx)
	if err != nil {
		zlog.Error(ctx).Err(err).Msg("errors encountered during updater run")
	}

	// perform run on every tick
	zlog.Info(ctx).Str("interval", m.interval.String()).Msg("starting background updates")
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			err := m.Run(ctx)
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("errors encountered during updater run")
			}
		}
	}
}

// Run constructs updaters from factories, configures them and runs them
// in batches.
//
// Run is safe to call at anytime, regardless of whether background updaters
// are running.
func (m *Manager) Run(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/updates/Manager.Run")

	updaters := []driver.Updater{}
	// Constructing updater sets may require network access
	// depending on the factory.
	// If construction fails, we will simply ignore those updater
	// sets.
	for _, factory := range m.factories {
		updateTime := time.Now()
		set, err := factory.UpdaterSet(ctx)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed constructing factory, excluding from run")
			continue
		}
		if stubUpdaterInSet(set) {
			updaterSetName, err := getFactoryNameFromStubUpdater(set)
			if err != nil {
				zlog.Error(ctx).
					Err(err).
					Msg("error getting updater set name")
			}
			err = m.store.RecordUpdaterSetStatus(ctx, updaterSetName, updateTime)
			if err != nil {
				zlog.Error(ctx).
					Err(err).
					Str("updaterSetName", updaterSetName).
					Time("updateTime", updateTime).
					Msg("error while recording update success for all updaters in updater set")
			}
			continue
		}
		updaters = append(updaters, set.Updaters()...)
	}

	// configure updaters
	toRun := make([]driver.Updater, 0, len(updaters))
	for _, u := range updaters {
		if f, ok := u.(driver.Configurable); ok {
			name := u.Name()
			cfg := m.configs[name]
			if cfg == nil {
				cfg = noopConfig
			}
			if err := f.Configure(ctx, cfg, m.client); err != nil {
				zlog.Warn(ctx).
					Err(err).
					Str("updater", name).
					Msg("failed configuring updater, excluding from current run")
				continue
			}
		}
		toRun = append(toRun, u)
	}

	zlog.Info(ctx).
		Int("total", len(toRun)).
		Int("batchSize", m.batchSize).
		Msg("running updaters")

	sem := semaphore.NewWeighted(int64(m.batchSize))
	errChan := make(chan error, len(toRun)+1) // +1 for a potential ctx error
	for i := range toRun {
		err := sem.Acquire(ctx, 1)
		if err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("sem acquire failed, ending updater run")
			break
		}

		go func(u driver.Updater) {
			defer sem.Release(1)

			ctx, done := m.locks.TryLock(ctx, u.Name())
			defer done()
			if err := ctx.Err(); err != nil {
				zlog.Debug(ctx).
					Err(err).
					Str("updater", u.Name()).
					Msg("lock context canceled, excluding from run")
				return
			}

			err = m.driveUpdater(ctx, u)
			if err != nil {
				errChan <- fmt.Errorf("%v: %w", u.Name(), err)
			}
		}(toRun[i])
	}

	// Unconditionally wait for all in-flight go routines to return.
	// The use of context.Background and lack of error checking is intentional.
	// All in-flight goroutines are guaranteed to release their semaphores.
	sem.Acquire(context.Background(), int64(m.batchSize))

	if m.updateRetention != 0 {
		ctx, done := m.locks.TryLock(ctx, "garbage-collection")
		if err := ctx.Err(); err != nil {
			zlog.Debug(ctx).
				Err(err).
				Msg("lock context canceled, garbage collection already running")
		} else {
			zlog.Info(ctx).Int("retention", m.updateRetention).Msg("GC started")
			i, err := m.store.GC(ctx, m.updateRetention)
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("error while performing GC")
			} else {
				zlog.Info(ctx).
					Int64("remaining_ops", i).
					Int("retention", m.updateRetention).
					Msg("GC completed")
			}
		}
		done()
	}

	close(errChan)
	if len(errChan) != 0 {
		var b strings.Builder
		b.WriteString("updating errors:\n")
		for err := range errChan {
			fmt.Fprintf(&b, "%v\n", err)
		}
		return errors.New(b.String())
	}
	return nil
}

// stubUpdaterInSet works out if an updater set contains a stub updater,
// signifying all updaters are up to date for this factory
func stubUpdaterInSet(set driver.UpdaterSet) bool {
	if len(set.Updaters()) == 1 {
		if set.Updaters()[0].Name() == "rhel-all" {
			return true
		}
	}
	return false
}

// getFactoryNameFromStubUpdater retrieves the factory name from an updater set with a stub updater
func getFactoryNameFromStubUpdater(set driver.UpdaterSet) (string, error) {
	if set.Updaters()[0].Name() == "rhel-all" {
		return "RHEL", nil
	}
	return "", errors.New("unrecognized stub updater name")
}

// DriveUpdater performs the business logic of fetching, parsing, and loading
// vulnerabilities discovered by an updater into the database.
func (m *Manager) driveUpdater(ctx context.Context, u driver.Updater) (err error) {
	var newFP driver.Fingerprint
	updateTime := time.Now()
	defer func() {
		deferErr := m.store.RecordUpdaterStatus(ctx, u.Name(), updateTime, newFP, err)
		if deferErr != nil {
			zlog.Error(ctx).
				Err(deferErr).
				Str("updater", u.Name()).
				Time("updateTime", updateTime).
				Msg("error while recording updater status")
		}
	}()

	name := u.Name()
	ctx = zlog.ContextWithValues(ctx,
		"component", "libvuln/updates/Manager.driveUpdater",
		"updater", name)
	zlog.Info(ctx).Msg("starting update")
	defer zlog.Info(ctx).Msg("finished update")
	uoKind := driver.VulnerabilityKind

	eu, euOK := u.(driver.EnrichmentUpdater)
	if euOK {
		zlog.Info(ctx).
			Msg("found EnrichmentUpdater")
		uoKind = driver.EnrichmentKind
	}

	var prevFP driver.Fingerprint
	opmap, err := m.store.GetUpdateOperations(ctx, uoKind, name)
	if err != nil {
		return
	}

	if s := opmap[name]; len(s) > 0 {
		prevFP = s[0].Fingerprint
	}

	var vulnDB io.ReadCloser
	switch {
	case euOK:
		vulnDB, newFP, err = eu.FetchEnrichment(ctx, prevFP)
	default:
		vulnDB, newFP, err = u.Fetch(ctx, prevFP)
	}
	if vulnDB != nil {
		defer vulnDB.Close()
	}
	switch {
	case err == nil:
	case errors.Is(err, driver.Unchanged):
		zlog.Info(ctx).Msg("vulnerability database unchanged")
		err = nil
		return
	default:
		return
	}

	var ref uuid.UUID
	switch {
	case euOK:
		var ers []driver.EnrichmentRecord
		ers, err = eu.ParseEnrichment(ctx, vulnDB)
		if err != nil {
			err = fmt.Errorf("enrichment database parse failed: %v", err)
			return
		}

		ref, err = m.store.UpdateEnrichments(ctx, name, newFP, ers)
	default:
		var vulns []*claircore.Vulnerability
		vulns, err = u.Parse(ctx, vulnDB)
		if err != nil {
			err = fmt.Errorf("vulnerability database parse failed: %v", err)
			return
		}

		ref, err = m.store.UpdateVulnerabilities(ctx, name, newFP, vulns)
	}
	if err != nil {
		err = fmt.Errorf("failed to update: %v", err)
		return
	}
	zlog.Info(ctx).
		Str("ref", ref.String()).
		Msg("successful update")
	return nil
}

// NoopConfig is used when an explicit config is not provided.
func noopConfig(_ interface{}) error { return nil }
