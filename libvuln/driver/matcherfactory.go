package driver

import (
	"context"

	"net/http"
)

// MatcherFactory is used to construct matchers at run-time.
type MatcherFactory interface {
	Matcher(context.Context) ([]Matcher, error)
}

// MatcherConfigUnmarshaler can be thought of as an Unmarshal function with the byte
// slice provided, or a Decode function.
//
// The function should populate a passed struct with any configuration
// information.
type MatcherConfigUnmarshaler func(interface{}) error

// MatcherConfigurable is an interface that MatcherFactory can implement to opt-in to having
// their configuration provided dynamically.
type MatcherConfigurable interface {
	Configure(context.Context, MatcherConfigUnmarshaler, *http.Client) error
}

// MatcherFactoryFunc would ease the registration of Matchers which don't
// need Configurability.
type MatcherFactoryFunc func(context.Context) ([]Matcher, error)

func (u MatcherFactoryFunc) Matcher(ctx context.Context) ([]Matcher, error) {
	return u(ctx)
}

// MatcherStatic creates an MatcherFactoryFunc returning the provided matcher.
func MatcherStatic(s Matcher) MatcherFactory {
	return MatcherFactoryFunc(func(_ context.Context) ([]Matcher, error) {
		return []Matcher{s}, nil
	})
}
