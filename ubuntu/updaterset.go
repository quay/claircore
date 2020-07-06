package ubuntu

import (
	"context"
	"net/http"
	"runtime"
	"sync"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
)

// Releases is a list of supported ubuntu releases.
var Releases = []Release{
	Bionic,
	Cosmic,
	Disco,
	Trusty,
	Xenial,
	Focal,
	Eoan,
}

// Factory implements driver.UpdaterSetFactory.
//
// A Factory should be constructed directly.
type Factory struct {
	Releases []Release
}

// UpdaterSet returns updaters for all releases that have available databases.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ubuntu/Factory/UpdaterSet").
		Logger()
	ctx = log.WithContext(ctx)

	us := make([]*Updater, len(f.Releases))
	ch := make(chan int, len(f.Releases))
	var wg sync.WaitGroup
	for i, lim := 0, runtime.NumCPU(); i < lim; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := ctx.Done()
			for i := range ch {
				select {
				case <-done:
					return
				default:
				}
				log := log.With().
					Str("release", string(us[i].release)).
					Logger()
				req, err := http.NewRequestWithContext(ctx, http.MethodHead, us[i].url, nil)
				if err != nil {
					log.Warn().Err(err).Msg("unable to create request")
					us[i] = nil
					return
				}
				res, err := http.DefaultClient.Do(req)
				if res != nil {
					res.Body.Close()
				}
				if err != nil || res.StatusCode != http.StatusOK {
					ev := log.Info()
					if err != nil {
						ev = ev.Err(err)
					} else {
						ev = ev.Int("status_code", res.StatusCode)
					}
					ev.Msg("ignoring release")
					us[i] = nil
				}
			}
		}()
	}

	for i, r := range f.Releases {
		us[i] = NewUpdater(r)
		ch <- i
	}
	close(ch)
	wg.Wait()

	set := driver.NewUpdaterSet()
	if err := ctx.Err(); err != nil {
		return set, err
	}
	for _, u := range us {
		if u == nil {
			continue
		}
		if err := set.Add(u); err != nil {
			return set, err
		}
	}
	return set, nil
}
