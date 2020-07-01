package updater

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"sync"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
)

// Executor is a helper for managing locks and state for updaters.
//
// An Executor should be constructed via a literal and is safe for concurrent
// use.
type Executor struct {
	Pool    *pgxpool.Pool
	Workers int

	// If the Filter member is provided, the updater set's names will be passed
	// through it.
	Filter func(name string) (keep bool)
}

// Run runs all the Updaters fed down the channel.
//
// The method runs until the provided channel is closed or the context is
// cancelled.
func (e *Executor) Run(ctx context.Context, ch <-chan driver.Updater) error {
	runID := rand.Uint32()
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/updater/Executor").
		Uint32("run_id", runID).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	var store vulnstore.Updater = postgres.NewVulnStore(e.Pool)
	filter := func(_ string) bool { return true }
	if f := e.Filter; f != nil {
		filter = f
	}
	w := runtime.NumCPU()
	if e.Workers > 0 {
		w = e.Workers
	}

	errs := &errmap{m: make(map[string]error)}
	var wg sync.WaitGroup
	wg.Add(w)
	for i := 0; i < w; i++ {
		go func() {
			defer wg.Done()
			var u driver.Updater
			var ok bool
			for {
				select {
				case <-ctx.Done():
				case u, ok = <-ch:
					if !ok {
						return
					}
				}

				name := u.Name()
				log := log.With().
					Str("updater", name).
					Logger()
				ctx := log.WithContext(ctx)

				if !filter(name) {
					log.Debug().Msg("filtered")
					continue
				}

				lock := distlock.NewPool(e.Pool, 0)
				ok, err := lock.TryLock(ctx, name)
				if err != nil {
					errs.add(name, err)
					return
				}
				if !ok {
					log.Debug().Msg("lock held, skipping")
					return
				}

				err = driveUpdater(ctx, log, u, store)
				lock.Unlock()
				if err != nil {
					errs.add(name, err)
				}
			}
		}()
	}
	wg.Wait()

	if errs.len() != 0 {
		return errs.error()
	}
	return nil
}

// Errmap is a wrapper around a group of errors.
type errmap struct {
	sync.Mutex
	m map[string]error
}

func (e errmap) add(name string, err error) {
	e.Lock()
	defer e.Unlock()
	e.m[name] = err
}

func (e errmap) len() int {
	e.Lock()
	defer e.Unlock()
	return len(e.m)
}

func (e errmap) error() error {
	e.Lock()
	defer e.Unlock()
	var b strings.Builder
	b.WriteString("updating errors:\n")
	for n, err := range e.m {
		fmt.Fprintf(&b, "\t%s: %v\n", n, err)
	}
	return errors.New(b.String())
}

// DriveUpdater drives the updater.
//
// The caller is expected to handle any locking or concurrency control needed.
func driveUpdater(ctx context.Context, log zerolog.Logger, u driver.Updater, s vulnstore.Updater) error {
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	name := u.Name()

	var prevFP driver.Fingerprint
	// Get previous fingerprint, if present.
	// A fingerprint being missing is not an error.
	opmap, err := s.GetUpdateOperations(ctx, name)
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
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	ref, err := s.UpdateVulnerabilities(ctx, name, newFP, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %v", err)
	}

	log.Info().
		Str("ref", ref.String()).
		Msg("successful update")
	return nil
}
