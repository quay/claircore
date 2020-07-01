package suse

import (
	"context"
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

var suseReleases = []Release{
	EnterpriseServer15,
	EnterpriseServer12,
	EnterpriseServer11,
	Leap150,
	Leap151,
}

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range suseReleases {
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
