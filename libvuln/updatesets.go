package libvuln

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/libvuln/driver"
)

// RunUpdaters runs all updaters from all configured updater factories.
//
// Any concurrency control is done at the UpdaterSet level. If Updaters want
// additional concurrency control, they must arrange it.
func (l *Libvuln) RunUpdaters(ctx context.Context, workers int, fs ...driver.UpdaterSetFactory) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/Libvuln/RunUpdaters").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("sets", len(fs)).
		Int("workers", workers).
		Msg("running updaters")

	ch := make(chan driver.Updater, workers)
	exe := updater.Executor{
		Pool:    l.pool,
		Workers: workers,
	}
	go func() {
		defer close(ch)
		for _, f := range fs {
			us, err := f.UpdaterSet(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("failed creating updaters")
				continue
			}
			for _, u := range us.Updaters() {
				select {
				case ch <- u:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	if err := exe.Run(ctx, ch); err != nil {
		log.Warn().Err(err).Msg("failed running updaters")
	}
	return nil
}

func (l *Libvuln) loopUpdaters(ctx context.Context, p time.Duration, w int, fs ...driver.UpdaterSetFactory) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/Libvuln/loopUpdaters").
		Logger()
	ctx = log.WithContext(ctx)
	t := time.NewTicker(p)
	defer t.Stop()
	done := ctx.Done()

	for {
		select {
		case <-done:
			return
		case <-t.C:
			if err := l.RunUpdaters(ctx, w, fs...); err != nil {
				log.Error().Err(err).Msg("unable to run updaters")
				return
			}
		}
	}
}
