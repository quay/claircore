package driver

import (
	"context"

	"net/http"
)

// MatcherFactory is used to construct matchers at run-time.
type MatcherFactory interface {
	Matcher(context.Context) (Matcher, error)
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
