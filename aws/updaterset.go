package aws

import (
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

var amazonReleases = []Release{
	Linux1,
	Linux2,
}

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range amazonReleases {
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
