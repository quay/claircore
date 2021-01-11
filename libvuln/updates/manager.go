package updates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/quay/claircore/updater"
	"github.com/rs/zerolog"
)

const (
	DefaultInterval = time.Duration(30 * time.Minute)
)

var (
	DefaultBatchSize = runtime.NumCPU()
)

type Configs map[string]driver.ConfigUnmarshaler

// Manager oversees the configuration and invocation of vulstore updaters.
//
// The Manager may be used in a one-shot fashion, configured
// to run background jobs, or both.
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
	// provided to construct distributed locks.
	// TODO(louis): this will be replaced by newest distlock implementation.
	pool   *pgxpool.Pool
	client *http.Client
	store  vulnstore.Updater
}

// NewManager will return a manager ready to have its Start or Run methods called.
func NewManager(ctx context.Context, store vulnstore.Updater, pool *pgxpool.Pool, client *http.Client, opts ...ManagerOption) (*Manager, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/NewManager").
		Logger()
	ctx = log.WithContext(ctx)

	if client == nil {
		client = http.DefaultClient
	}

	// the default Manager
	m := &Manager{
		store:     store,
		pool:      pool,
		factories: updater.Registered(),
		batchSize: DefaultBatchSize,
		interval:  DefaultInterval,
		client:    client,
	}

	// these options can be ran order independent.
	for _, opt := range opts {
		opt(m)
	}

	err := updater.Configure(ctx, m.factories, m.configs, m.client)
	if err != nil {
		return nil, fmt.Errorf("failed to configure updater set factory: %w", err)
	}

	return m, nil
}

// Start will run updaters at the given interval.
//
// Start is designed to be ran as a go routine.
// Cancel the provided ctx to end the updater loop.
func (m *Manager) Start(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/Manager.Start").
		Logger()
	ctx = log.WithContext(ctx)
	if m.interval == 0 {
		return fmt.Errorf("manager must be configured with an interval to start")
	}
	log.Info().Str("interval", m.interval.String()).Msg("starting background updates")

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

// Run constructs updaters from factories, configures them
// and runs them in Manager.batchSize batches.
//
// Run is safe to call at anytime, regardless of whether
// background updaters are running.
func (m *Manager) Run(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/Manager.Run").
		Logger()
	ctx = log.WithContext(ctx)

	updaters := []driver.Updater{}
	// constructing updater sets may require network access,
	// depending on the factory.
	// if construction fails we will simply ignore those updater
	// sets.
	for _, factory := range m.factories {
		set, err := factory.UpdaterSet(ctx)
		if err != nil {
			log.Error().Err(err).Msg("failed constructing factory, excluding from run")
			continue
		}
		updaters = append(updaters, set.Updaters()...)
	}

	// reconfigure updaters
	for _, u := range updaters {
		f, fOK := u.(driver.Configurable)
		cfg, cfgOK := m.configs[u.Name()]
		if fOK && cfgOK {
			if err := f.Configure(ctx, cfg, nil); err != nil {
				log.Warn().Err(err).Str("updater", u.Name()).Msg("failed configuring updater, excluding from current run")
				continue
			}
		}
	}

	log.Info().Int("total", len(updaters)).Int("batchSize", m.batchSize).Msg("running updaters")

	sem := semaphore.NewWeighted(int64(m.batchSize))
	errChan := make(chan error, len(updaters)+1) // +1 for a potential ctx error
	for i := range updaters {

		err := sem.Acquire(ctx, 1)
		if err != nil {
			log.Err(err).Msg("sem acquire failed, ending updater run.")
			break
		}

		go func(u driver.Updater) {
			defer sem.Release(1)

			if err := ctx.Err(); err != nil {
				return
			}

			if m.pool != nil {
				lock := postgres.NewPool(m.pool, 0)
				ok, err := lock.TryLock(ctx, u.Name())
				if err != nil {
					errChan <- err
					return
				}
				if !ok {
					log.Debug().Str("updater", u.Name()).Msg("another process running updater, excluding from run.")
					return
				}
				defer lock.Unlock()
			}

			err = m.driveUpdater(ctx, u)
			if err != nil {
				errChan <- fmt.Errorf("%v: %w\n", u.Name(), err)
			}
		}(updaters[i])
	}

	// unconditionally wait for all in-flight go routines to return.
	// the use of context.Background and lack of error checking is intentional.
	// all in-flight go routines are gauranteed to release their sems.
	sem.Acquire(context.Background(), int64(m.batchSize))

	close(errChan)
	if len(errChan) != 0 {
		var b strings.Builder
		b.WriteString("Updating errors:\n")
		for err := range errChan {
			fmt.Fprintf(&b, "%v\n", err)
		}
		return errors.New(b.String())
	}
	return nil
}

// driveUpdaters perform the business logic of fetching, parsing, and loading
// vulnerabilities discovered by an updater into the database.
func (m *Manager) driveUpdater(ctx context.Context, u driver.Updater) error {
	name := u.Name()
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/Manager.driveUpdater").
		Str("updater", name).
		Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("starting update")

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
		log.Info().Msg("vulnerability database unchanged")
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

	log.Info().Msg("finished update")
	return nil
}
