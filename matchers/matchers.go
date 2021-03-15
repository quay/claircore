package matchers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

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
}

type MatchersOption func(m *Matchers)

// NewManager will return a manager ready to have its Start or Run methods called.
func NewMatchers(ctx context.Context, client *http.Client, opts ...MatchersOption) ([]driver.Matcher, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/matchers/NewMatchers"))

	if client == nil {
		client = http.DefaultClient
	}

	// the default Manager
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
		return nil, fmt.Errorf("failed to configure updater set factory: %w", err)
	}

	matchers := []driver.Matcher{}
	// constructing updater sets may require network access,
	// depending on the factory.
	// if construction fails we will simply ignore those updater
	// sets.
	for _, factory := range m.factories {
		matcher, err := factory.Matcher(ctx)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed constructing factory, excluding from run")
			continue
		}
		matchers = append(matchers, matcher)
	}
	return matchers, nil
}
