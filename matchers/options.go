package matchers

import (
	"github.com/quay/claircore/libvuln/driver"
)

// WithEnabled configures the Matchers to only run the specified
// matchers.
//
// If enabled == nil all default matchers will run (same as not providing this option to the constructor at all).
// If len(enabled) == 0 no default matchers will run.
// If len(enabled) > 0 only provided matchers will be ran.
func WithEnabled(enabled []string) MatchersOption {
	return func(m *Matchers) {
		if enabled == nil {
			return
		}

		factories := map[string]driver.MatcherFactory{}
		for _, enable := range enabled {
			for name, factory := range m.factories {
				if name == enable {
					factories[name] = factory
				}
			}
		}
		m.factories = factories
	}
}

// WithConfigs tells the Matchers to configure each matcher where
// a configuration is provided.
//
// Configuration of individual matchers is delegated to matchers/registry/registry.go
// Note: this option is optimal when ran after WithEnabled option. However,
// this option has no strict depedency on others.
func WithConfigs(cfgs Configs) MatchersOption {
	return func(m *Matchers) {
		m.configs = cfgs
	}
}

// WithOutOfTree allows callers to provide their own out-of-tree
// matchers.
func WithOutOfTree(outOfTree []driver.Matcher) MatchersOption {
	return func(m *Matchers) {
		m.matchers = outOfTree
	}
}
