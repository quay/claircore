package rhel

import (
	"context"
	"net/http"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.MatcherFactory      = (*MatcherFactory)(nil)
	_ driver.MatcherConfigurable = (*MatcherFactory)(nil)
)

type MatcherFactory struct {
	ignoreUnpatched bool
}

// MatcherFactory implements [driver.MatcherFactory]
func (f *MatcherFactory) Matcher(ctx context.Context) ([]driver.Matcher, error) {
	m := &Matcher{
		ignoreUnpatched: f.ignoreUnpatched,
	}
	return []driver.Matcher{m}, nil
}

type MatcherFactoryConfig struct {
	IgnoreUnpatched bool `json:"ignore_unpatched" yaml:"ignore_unpatched"`
}

// MatcherFactory implements driver.MatcherConfigurable.
func (f *MatcherFactory) Configure(ctx context.Context, cfg driver.MatcherConfigUnmarshaler, _ *http.Client) error {
	var fc MatcherFactoryConfig
	if err := cfg(&fc); err != nil {
		return err
	}
	f.ignoreUnpatched = fc.IgnoreUnpatched
	zlog.Info(ctx).
		Str("component", "rhel/MatcherFactory.Configure").
		Bool("ignore_unpatched", f.ignoreUnpatched).
		Msg("configured")
	return nil
}
