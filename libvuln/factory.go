package libvuln

import (
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/ubuntu"
)

// MatcherFactory is a factory method which returns Matchers used during libvuln runtime.
type MatcherFactory func() []matcher.Matcher

// matcherFactory is the default MatcherFactory method
func matcherFactory() []matcher.Matcher {
	return []matcher.Matcher{
		&ubuntu.Matcher{},
	}
}

// UpdaterFactory is a factory method which returns Updaters used during libvuln runtime.
type UpdaterFactory func() []updater.Updater

// updaterFactory is the default UpdaterFactory
func updaterFactory() []updater.Updater {
	return []updater.Updater{
		ubuntu.NewUpdater(ubuntu.Artful),
		ubuntu.NewUpdater(ubuntu.Bionic),
		ubuntu.NewUpdater(ubuntu.Cosmic),
		ubuntu.NewUpdater(ubuntu.Disco),
		ubuntu.NewUpdater(ubuntu.Precise),
		ubuntu.NewUpdater(ubuntu.Trusty),
		ubuntu.NewUpdater(ubuntu.Xenial),
	}
}
