package bodhi

import (
	"context"
	"net/url"

	"github.com/quay/zlog"

	driver "github.com/quay/claircore/updater/driver/v1"
)

var _ driver.UpdaterFactory = (*Factory)(nil)

// Factory creates [driver.Updater]s talking to a configured API URL.
type Factory struct {
	_ struct{} // Hide that there's nothing here from the documentation.
}

// NewFactory returns a Factory.
func NewFactory(ctx context.Context) (*Factory, error) {
	return (*Factory)(nil), nil
}

// FactoryConfig is the configuration of a Factory.
type FactoryConfig struct {
	API *string `json:"api" yaml:"api"`
}

// Name implements [driver.UpdaterFactory].
func (*Factory) Name() string { return "bodhi" }

// UpdaterSet implements [driver.UpdaterFactory].
func (f *Factory) Create(ctx context.Context, cf driver.ConfigUnmarshaler) ([]driver.Updater, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "updater/bodhi/Factory.Configure",
	)
	root := defaultAPI
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return nil, err
	}

	if cfg.API != nil {
		var err error
		root, err = url.Parse(*cfg.API)
		if err != nil {
			return nil, err
		}
		zlog.Info(ctx).
			Stringer("url", root).
			Msg("configured API URL")
	}
	return []driver.Updater{&Updater{root: root}}, nil
}
