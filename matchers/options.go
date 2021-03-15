package matchers

import (
	"github.com/quay/claircore/libvuln/driver"
)

// WithEnabled configures the Matchers to only run the specified
// updater sets.
//
// If enabled == nil all default updater sets will run (same as not providing this option to the constructor at all).
// If len(enabled) == 0 no default updater sets will run.
// If len(enabled) > 0 only provided updater sets will be ran.
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

// WithConfigs tells the Matchers to configure each updater where
// a configuration is provided.
//
// Configuration of individual updaters is delegated to updater/registry.go
// Note: this option is optimal when ran after WithEnabled option. However,
// this option has no strict depedency on others.
func WithConfigs(cfgs Configs) MatchersOption {
	return func(m *Matchers) {
		m.configs = cfgs
	}
}

// WithOutOfTree allows callers to provide their own out-of-tree
// updaters.
//
// note: currently we will never configure the outOfTree updater
// factory. if this changes consider making this option a required
// to avoid missing configuration
// func WithOutOfTree(outOfTree []driver.Updater) MatchersOption {
// 	return func(m *Matchers) {
// 		us := driver.NewUpdaterSet()
// 		for _, u := range outOfTree {
// 			if err := us.Add(u); err != nil {
// 				// duplicate updater, ignore.
// 				continue
// 			}
// 		}
// 		m.factories["outOfTree"] = driver.StaticSet(us)
// 	}
// }
