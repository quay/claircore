package libvuln

import (
	"context"
	"fmt"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/pyupio"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
	"github.com/rs/zerolog"
)

var defaultSets = map[string]func() (driver.UpdaterSet, error){
	"alpine": alpine.UpdaterSet,
	"aws":    aws.UpdaterSet,
	"debian": debian.UpdaterSet,
	"oracle": oracle.UpdaterSet,
	"photon": photon.UpdaterSet,
	"pyupio": pyupio.UpdaterSet,
	"rhel":   rhel.UpdaterSet,
	"suse":   suse.UpdaterSet,
	"ubuntu": ubuntu.UpdaterSet,
}

// UpdaterSets returns all UpdaterSets currently
// supported by libvuln
func updaterSets(ctx context.Context, sets []string) (driver.UpdaterSet, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updaterSets").
		Logger()

	us := driver.NewUpdaterSet()
	var set driver.UpdaterSet
	var err error
	switch {
	// merge all sets
	case sets == nil:
		log.Info().
			Msg("creating all default updater sets")

		for name, f := range defaultSets {
			set, err = f()
			if err != nil {
				return us, fmt.Errorf("failed to create %s updater set: %v", name, err)
			}

			err = us.Merge(set)
			if err != nil {
				return us, fmt.Errorf("failed to merge set %s: %v", name, err)
			}
		}
		return us, nil

	// merge only supplied sets
	case len(sets) > 0:
		log.Info().Str("sets", fmt.Sprintf("%v", sets)).
			Msg("creating specified updater sets")

		for _, name := range sets {
			if _, ok := defaultSets[name]; !ok {
				log.Warn().Str("set", name).Msg("unknown update set provided")
				continue
			}

			set, err = defaultSets[name]()
			if err != nil {
				return us, fmt.Errorf("failed to create %s updater set: %v", name, err)
			}

			err = us.Merge(set)
			if err != nil {
				return us, fmt.Errorf("failed to merge set %s: %v", name, err)
			}
		}
	}
	return us, nil
}
