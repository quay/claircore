package libvuln

import (
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
)

// UpdaterSets returns all UpdaterSets currently
// supported by libvuln
func updaterSets() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	var set driver.UpdaterSet
	var err error

	set, err = alpine.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created alpine updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = aws.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created aws updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = debian.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created debian updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = oracle.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created oracle updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = photon.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created photon updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = pyupio.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created pyupio updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = rhel.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created rhel updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = suse.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created suse updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	set, err = ubuntu.UpdaterSet()
	if err != nil {
		return us, fmt.Errorf("failed to created ubuntu updater set: %v", err)
	}
	err = us.Merge(set)
	if err != nil {
		return us, err
	}

	return us, nil
}
