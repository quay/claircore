package crda

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
)

// Factory contains the configuration to connect with CRDA remote matcher.
type Factory struct {
	url        *url.URL
	client     *http.Client
	ecosystems []string
}

// MatcherFactory implements driver.MatcherFactory.
func (f *Factory) Matcher(ctx context.Context) ([]driver.Matcher, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "crda/MatcherFactory.Matcher"))
EcosystemSubSet:
	for _, e := range f.ecosystems {
		for _, se := range supportedEcosystems {
			if e == se {
				continue EcosystemSubSet
			}
		}
		return nil, fmt.Errorf("invalid ecosystems:%#v", f.ecosystems)
	}

	if len(f.ecosystems) > 0 {
		zlog.Info(ctx).
			Msg("using configured ecosystems")
	} else {
		f.ecosystems = supportedEcosystems
		zlog.Info(ctx).
			Msg("using default ecosystems")
	}

	var matchers []driver.Matcher
	for _, e := range f.ecosystems {
		m, err := NewMatcher(e, WithClient(f.client), WithURL(f.url))
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

// To decode the config.
type FactoryConfig struct {
	URL        string   `json:"url" yaml:"url"`
	Ecosystems []string `json:"ecosystems" yaml:"ecosystems"`
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
	f.ecosystems = fc.Ecosystems
	return nil
}