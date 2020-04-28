package ubuntu

import (
	"github.com/quay/claircore/libvuln/driver"
)

// ubuntuReleases is a list of supported
// ubuntu releases.
var ubuntuReleases = []Release{
	Bionic,
	Cosmic,
	Disco,
	Trusty,
	Xenial,
	Focal,
	Eoan,
}

// UpdaterSet returns a UpdaterSet comprised of
// all supported ubuntu releases.
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
