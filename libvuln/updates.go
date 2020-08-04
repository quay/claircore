package libvuln

import (
	"context"
	"io"
	"net/http"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/libvuln/driver"
)

func NewUpdater(pool *pgxpool.Pool, client *http.Client, config map[string]driver.ConfigUnmarshaler, workers int, filter func(string) bool) (*UpdateDriver, error) {
	return &UpdateDriver{
		exe: &updater.Online{
			Pool:    pool,
			Workers: workers,
			Filter:  filter,
		},
		client: client,
		config: config,
	}, nil
}

func NewOfflineUpdater(config map[string]driver.ConfigUnmarshaler, filter func(string) bool, out io.Writer) (*UpdateDriver, error) {
	return &UpdateDriver{
		exe: &updater.Offline{
			Filter: filter,
			Output: out,
		},
		config: config,
	}, nil
}

type UpdateDriver struct {
	exe    updater.Controller
	client *http.Client
	config map[string]driver.ConfigUnmarshaler
}

func (d *UpdateDriver) RunUpdaters(ctx context.Context, fs ...driver.UpdaterSetFactory) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updateDriver/RunUpdaters").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("sets", len(fs)).
		Msg("running updaters")

	ch := make(chan driver.Updater, 10)
	go func() {
		defer close(ch)
		for _, f := range fs {
			us, err := f.UpdaterSet(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("failed creating updaters")
				continue
			}
			for _, u := range us.Updaters() {
				f, fOK := u.(driver.Configurable)
				cfg, cfgOK := d.config[u.Name()]
				if fOK && cfgOK {
					if err := f.Configure(ctx, cfg, d.client); err != nil {
						log.Warn().Err(err).Msg("failed creating updaters")
						continue
					}
				}
				select {
				case ch <- u:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return d.exe.Run(ctx, ch)
}
