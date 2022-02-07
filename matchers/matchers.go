package matchers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	_ "github.com/quay/claircore/matchers/defaults"
	"github.com/quay/claircore/matchers/registry"
)

type Configs map[string]driver.MatcherConfigUnmarshaler

type Matchers struct {
	// provides run-time matcher construction.
	factories map[string]driver.MatcherFactory
	// configs provided to matchers once constructed.
	configs Configs
	client  *http.Client
	// out-of-tree matchers.
	matchers []driver.Matcher
}

type MatchersOption func(m *Matchers)

// NewMatchers will return a slice of Matcher created based on the provided
// MatchersOption.
func NewMatchers(ctx context.Context, client *http.Client, opts ...MatchersOption) ([]driver.Matcher, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/matchers/NewMatchers")
	if client == nil {
		return nil, errors.New("invalid *http.Client")
	}

	m := &Matchers{
		factories: registry.Registered(),
		client:    client,
	}

	// these options can be ran order independent.
	for _, opt := range opts {
		opt(m)
	}

	err := registry.Configure(ctx, m.factories, m.configs, m.client)
	if err != nil {
		return nil, fmt.Errorf("failed to configure matchers factory: %w", err)
	}

	matchers := []driver.Matcher{}
	// constructing matchers may return error,
	// depending on the factory.
	// if construction fails we will simply ignore those matcher.
	for _, factory := range m.factories {
		matcher, err := factory.Matcher(ctx)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed constructing factory, excluding from run")
			continue
		}
		matchers = append(matchers, matcher...)
	}

	// merge default matchers with any out-of-tree specified.
	matchers = append(matchers, m.matchers...)

	return matchers, nil
}
