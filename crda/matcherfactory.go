package crda

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

// Factory contains the configuration to connect to the CRDA remote matcher.
type Factory struct {
	url        *url.URL
	client     *http.Client
	source     string
	key        string
	ecosystems []string
}

// MatcherFactory implements driver.MatcherFactory.
func (f *Factory) Matcher(ctx context.Context) ([]driver.Matcher, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "crda/MatcherFactory.Matcher")

	if f.key == "" {
		zlog.Info(ctx).
			Msg("no key configured, skipping")
		return nil, nil
	}

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
	opts := []option{withClient(f.client)}
	if f.url != nil {
		opts = append(opts, withURL(f.url))
	}
	if f.source != "" {
		opts = append(opts, withSource(f.source))
	}
	for _, e := range f.ecosystems {
		m, err := newMatcher(e, f.key, opts...)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

// Config is the structure accepted to configure all matchers.
type Config struct {
	URL        string   `json:"url" yaml:"url"`
	Source     string   `json:"source" yaml:"source"`
	Key        string   `json:"key" yaml:"key"`
	Ecosystems []string `json:"ecosystems" yaml:"ecosystems"`
}

// MatcherFactory implements driver.MatcherConfigurable.
func (f *Factory) Configure(ctx context.Context, cfg driver.MatcherConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "crda/MatcherFactory.Configure")
	var fc Config

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
			Msg("configured API URL")
		f.url = u
	}
	if fc.Source != "" {
		f.source = fc.Source
		zlog.Info(ctx).
			Str("source", fc.Source).
			Msg("configured source")
	}
	if fc.Key != "" {
		f.key = fc.Key
		zlog.Info(ctx).
			Str("key", f.key).
			Msg("configured API key")
	}

	f.ecosystems = fc.Ecosystems
	return nil
}
