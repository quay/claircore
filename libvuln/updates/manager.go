package updates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/quay/claircore/updater"
)

const (
	DefaultInterval = time.Duration(30 * time.Minute)
)

var (
	DefaultBatchSize = runtime.NumCPU()
)

type Configs map[string]driver.ConfigUnmarshaler

// LockSource abstracts over how locks are implemented.
//
// An online system needs distributed locks, offline use cases can use
// process-local locks.
type LockSource interface {
	NewLock() distlock.Locker
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
	store  vulnstore.Updater
}

// NewManager will return a manager ready to have its Start or Run methods called.
func NewManager(ctx context.Context, store vulnstore.Updater, locks LockSource, client *http.Client, opts ...ManagerOption) (*Manager, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/updates/NewManager"))

	if client == nil {
		client = http.DefaultClient
	}

	// the default Manager
	m := &Manager{
		store:     store,
		locks:     locks,
		factories: updater.Registered(),
		batchSize: DefaultBatchSize,
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/updates/Manager.Start"))

	if m.interval == 0 {
		return fmt.Errorf("manager must be configured with an interval to start")
	}

	// perform the initial run
	zlog.Info(ctx).Msg("starting initial updates")
	m.Run(ctx) // errors reported via log messages internal to this call

	// perform run on every tick
	zlog.Info(ctx).Str("interval", m.interval.String()).Msg("starting background updates")
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			m.Run(ctx)
		}
	}
}

// Run constructs updaters from factories, configures them and runs them
// in batches.
//
// Run is safe to call at anytime, regardless of whether background updaters
// are running.
func (m *Manager) Run(ctx context.Context) error {
	ctx = baggage.ContextWithValues(
		ctx,
		label.String("component", "libvuln/updates/Manager.Run"),
	)

	updaters := []driver.Updater{}
	// Constructing updater sets may require network access
	// depending on the factory.
	// If construction fails, we will simply ignore those updater
	// sets.
	for _, factory := range m.factories {
		set, err := factory.UpdaterSet(ctx)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed constructing factory, excluding from run")
			continue
		}
		updaters = append(updaters, set.Updaters()...)
	}

	// configure updaters
	toRun := make([]driver.Updater, 0, len(updaters))
	for _, u := range updaters {
		f, fOK := u.(driver.Configurable)
		cfg, cfgOK := m.configs[u.Name()]
		if fOK && cfgOK {
			if err := f.Configure(ctx, cfg, nil); err != nil {
				zlog.Warn(ctx).Err(err).Str("updater", u.Name()).Msg("failed configuring updater, excluding from current run")
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

			if err := ctx.Err(); err != nil {
				return
			}

			lock := m.locks.NewLock()
			ok, err := lock.TryLock(ctx, u.Name())
			if err != nil {
				errChan <- err
				return
			}
			if !ok {
				zlog.Debug(ctx).
					Str("updater", u.Name()).
					Msg("another process running updater, excluding from run")
				return
			}
			defer lock.Unlock()

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

// DriveUpdater performs the business logic of fetching, parsing, and loading
// vulnerabilities discovered by an updater into the database.
func (m *Manager) driveUpdater(ctx context.Context, u driver.Updater) error {
	name := u.Name()
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/updates/Manager.driveUpdater"),
		label.String("updater", name),
	)
	zlog.Info(ctx).Msg("starting update")
	defer zlog.Info(ctx).Msg("finished update")

	var prevFP driver.Fingerprint
	opmap, err := m.store.GetUpdateOperations(ctx, name)
	if err != nil {
		return err
	}

	if s := opmap[name]; len(s) > 0 {
		prevFP = s[0].Fingerprint
	}

	vulnDB, newFP, err := u.Fetch(ctx, prevFP)
	if vulnDB != nil {
		defer vulnDB.Close()
	}
	switch {
	case err == nil:
	case errors.Is(err, driver.Unchanged):
		zlog.Info(ctx).Msg("vulnerability database unchanged")
		return nil
	default:
		return err
	}

	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("database parse failed: %w", err)
	}

	_, err = m.store.UpdateVulnerabilities(ctx, name, newFP, vulns)
	if err != nil {
		return fmt.Errorf("vulnstore update failed: %w", err)
	}

	return nil
}
