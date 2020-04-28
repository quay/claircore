package ubuntu

import (
	"github.com/quay/claircore/libvuln/driver"
)

var ubuntuReleases = []Release{
	Bionic,
	Cosmic,
	Disco,
	Trusty,
	Xenial,
}

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for _, release := range ubuntuReleases {
		u := NewUpdater(release)
		err := us.Add(u)
		if err != nil {
			return us, err
		}
	}
	return us, nil
}
