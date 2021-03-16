package crda

import (
	"context"
	"net/http"
	"net/url"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
)

// Factory contains the configuration to connect with CRDA remote matcher.
type Factory struct {
	url    *url.URL
	client *http.Client
}

// MatcherFactory implements driver.MatcherFactory.
func (f *Factory) Matcher(ctx context.Context) (driver.Matcher, error) {
	m, err := NewMatcher(WithClient(f.client), WithURL(f.url))
	if err != nil {
		return nil, err
	}
	return m, nil
}

// To decode the config.
type FactoryConfig struct {
	URL string `json:"url" yaml:"url"`
}

// MatcherFactory implements driver.MatcherConfigurable.
func (f *Factory) Configure(ctx context.Context, cfg driver.MatcherConfigUnmarshaler, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "crda/MatcherFactory.Configure"))
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	zlog.Debug(ctx).Msg("loaded incoming config")

	if fc.URL != "" {
		u, err := url.Parse(fc.URL)
		if err != nil {
			return err
		}
		zlog.Info(ctx).
			Str("url", u.String()).
			Msg("configured manifest URL")
		f.url = u
	}

	if c != nil {
		zlog.Info(ctx).
			Msg("configured HTTP client")
		f.client = c
	}

	return nil
}
