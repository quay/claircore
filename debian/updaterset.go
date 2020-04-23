package debian

import (
	"github.com/quay/claircore/libvuln/driver"
)

var debianReleases = []Release{
	Buster,
	Jessie,
	Stretch,
	Wheezy,
}

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range debianReleases {
		u := NewUpdater(release)
		err := us.Add(u)
		if err != nil {
			return us, err
		}
	}
	return us, nil
}
