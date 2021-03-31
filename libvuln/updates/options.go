package updates

import (
	"time"

	"github.com/quay/claircore/libvuln/driver"
)

// ManagerOption specify optional configuration for a Manager.
// Defaults will be used where options are not provided to the constructor.
type ManagerOption func(m *Manager)

// WithBatchSize sets the max number of parallel updaters that will run during an
// update interval.
func WithBatchSize(n int) ManagerOption {
	return func(m *Manager) {
		m.batchSize = n
	}
}

// WithInterval configures the interval at which updaters will be ran.
// The manager runs all configured updaters during an interval.
// Setting this duration too low may cause missed update intervals.
func WithInterval(interval time.Duration) ManagerOption {
	return func(m *Manager) {
		m.interval = interval
	}
}

// WithEnabled configures the Manager to only run the specified
// updater sets.
//
// If enabled == nil all default updater sets will run (same as not providing this option to the constructor at all).
// If len(enabled) == 0 no default updater sets will run.
// If len(enabled) > 0 only provided updater sets will be ran.
func WithEnabled(enabled []string) ManagerOption {
	return func(m *Manager) {
		if enabled == nil {
			return
		}

		factories := map[string]driver.UpdaterSetFactory{}
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

// WithConfigs tells the Manager to configure each updater where
// a configuration is provided.
//
// Configuration of individual updaters is delegated to updater/registry.go
// Note: this option is optimal when ran after WithEnabled option. However,
// this option has no strict depedency on others.
func WithConfigs(cfgs Configs) ManagerOption {
	return func(m *Manager) {
		m.configs = cfgs
	}
}

// WithOutOfTree allows callers to provide their own out-of-tree
// updaters.
//
// note: currently we will never configure the outOfTree updater
// factory. if this changes consider making this option a required
// to avoid missing configuration
func WithOutOfTree(outOfTree []driver.Updater) ManagerOption {
	return func(m *Manager) {
		us := driver.NewUpdaterSet()
		for _, u := range outOfTree {
			if err := us.Add(u); err != nil {
				// duplicate updater, ignore.
				continue
			}
		}
		m.factories["outOfTree"] = driver.StaticSet(us)
	}
}

// WithGC instructs the manager to run garbage collection
// at the end of an update interval.
//
// The provided retention value informs the manager how many
// update operations to keep.
func WithGC(retention int) ManagerOption {
	return func(m *Manager) {
		m.updateRetention = retention
	}
}

// WithFactories resets UpdaterSetFactories used by the Manager.
func WithFactories(f map[string]driver.UpdaterSetFactory) ManagerOption {
	return func(m *Manager) {
		m.factories = f
	}
}
