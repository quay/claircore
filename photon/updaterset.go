package photon

import (
	"context"
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

var photonReleases = []Release{
	Photon1,
	Photon2,
	Photon3,
}

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range photonReleases {
		u, err := NewUpdater(release)
		if err != nil {
			return us, fmt.Errorf("failed to create updater: %v", err)
		}
		err = us.Add(u)
		if err != nil {
			return us, err
		}
	}
	return us, nil
}
