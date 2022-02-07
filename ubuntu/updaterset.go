package ubuntu

import (
	"context"
	"net/http"
	"runtime"
	"sync"

	"github.com/quay/zlog"

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

var (
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
)

// Factory implements driver.UpdaterSetFactory.
//
// A Factory should be constructed directly, and Configure must be called to
// provide an http.Client.
type Factory struct {
	Releases []Release `json:"releases" yaml:"releases"`
	c        *http.Client
}

// FactoryConfig is the shadow type for marshaling, so we can tell if something
// was specified. The tags on the Factory above are just for documentation.
type factoryConfig struct {
	Releases []Release `json:"releases" yaml:"releases"`
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Factory.Configure")
	var cfg factoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.Releases != nil {
		f.Releases = cfg.Releases
		zlog.Info(ctx).
			Msg("configured releases")
	}

	f.c = c
	zlog.Info(ctx).
		Msg("configured HTTP client")
	return nil
}

// UpdaterSet returns updaters for all releases that have available databases.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Factory.UpdaterSet")

	us := make([]*Updater, len(f.Releases))
	ch := make(chan int, len(f.Releases))
	var wg sync.WaitGroup
	for i, lim := 0, runtime.GOMAXPROCS(0); i < lim; i++ {
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
				ctx := zlog.ContextWithValues(ctx, "release", string(us[i].release))
				req, err := http.NewRequestWithContext(ctx, http.MethodHead, us[i].url, nil)
				if err != nil {
					zlog.Warn(ctx).Err(err).Msg("unable to create request")
					us[i] = nil
					return
				}
				res, err := f.c.Do(req)
				if err != nil {
					zlog.Info(ctx).Err(err).Msg("ignoring release")
					us[i] = nil
					return
				}
				res.Body.Close()
				if res.StatusCode != http.StatusOK {
					zlog.Info(ctx).Int("status_code", res.StatusCode).Msg("ignoring release")
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
