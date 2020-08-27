package libvuln

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/internal/vulnstore/jsonblob"
	"github.com/quay/claircore/internal/vulnstore/postgres"
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

// OfflineImport takes the format written into the io.Writer provided to
// NewOfflineUpdater and imports the contents into the provided pgxpool.Pool.
func OfflineImport(ctx context.Context, pool *pgxpool.Pool, in io.Reader) error {
	// BUG(hank) The OfflineImport function is a wart, needed to work around
	// some package namespacing issues. It should get refactored if claircore
	// gets merged into clair.
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/OfflineImporter").
		Logger()
	ctx = log.WithContext(ctx)

	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()

	s := postgres.NewVulnStore(pool)
	l, err := jsonblob.Load(ctx, gz)
	if err != nil {
		return err
	}

	ops, err := s.GetUpdateOperations(ctx)
	if err != nil {
		return err
	}

Update:
	for l.Next() {
		e := l.Entry()
		for _, op := range ops[e.Updater] {
			// This only helps if updaters don't keep something that
			// changes in the fingerprint.
			if op.Fingerprint == e.Fingerprint {
				log.Info().
					Str("updater", e.Updater).
					Msg("fingerprint match, skipping")
				continue Update
			}
		}
		ref, err := s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln)
		if err != nil {
			return err
		}
		log.Info().
			Str("updater", e.Updater).
			Str("ref", ref.String()).
			Int("count", len(e.Vuln)).
			Msg("update imported")
	}
	if err := l.Err(); err != nil {
		return err
	}
	return nil
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
