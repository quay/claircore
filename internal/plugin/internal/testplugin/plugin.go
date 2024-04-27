// Package testplugin is a package to support the
// [github.com/quay/claircore/internal/plugin] tests.
package testplugin

import (
	"context"

	"github.com/quay/claircore/toolkit/registry"
)

const (
	// Name is the name used by this package's [registry.Register] call.
	Name = `urn:claircore:testplugin:interface:test`
	// Type is the stringified type of the concrete type implementing
	// [Interface].
	Type = `*testplugin.Implementation`
)

// Interface is an interface type for testing the plugin system.
type Interface interface {
	implement()
}

// Implementation implements [Interface].
type Implementation struct{}

func (*Implementation) implement() {}

// Plugintool auto-registration purposefully omitted.
func init() {
	registry.Register(Name, &registry.Description[Interface]{
		New: func(_ context.Context, f func(any) error) (Interface, error) {
			var discard struct{}
			f(&discard)
			return (*Implementation)(nil), nil
		},
	})
}
