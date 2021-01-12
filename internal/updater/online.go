package updater

import (
	"context"
	"math/rand"
	"runtime"
	"sync"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
)

// Online is a controller that writes updates to a database.
//
// An Online should be constructed via a literal and is safe for concurrent
// use.
type Online struct {
	Pool    *pgxpool.Pool
	Workers int

	// If the Filter member is provided, the updater set's names will be passed
	// through it.
	Filter func(name string) (keep bool)
}

var _ Controller = (*Online)(nil)

// Run runs all the Updaters fed down the channel.
//
// The method runs until the provided channel is closed or the context is
// cancelled.
func (e *Online) Run(ctx context.Context, ch <-chan driver.Updater) error {
	runID := rand.Uint32()
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/updater/Executor"),
		label.Uint32("run_id", runID))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

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
				ctx := baggage.ContextWithValues(ctx,
					label.String("updater", name))

				if !filter(name) {
					zlog.Debug(ctx).Msg("filtered")
					continue
				}

				lock := distlock.NewPool(e.Pool, 0)
				ok, err := lock.TryLock(ctx, name)
				if err != nil {
					errs.add(name, err)
					return
				}
				if !ok {
					zlog.Debug(ctx).Msg("lock held, skipping")
					return
				}

				err = driveUpdater(ctx, u, store)
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
