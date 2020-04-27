package rhel

import (
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

var rhelReleases = []Release{
	RHEL6,
	RHEL7,
	RHEL8,
}

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range rhelReleases {
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
