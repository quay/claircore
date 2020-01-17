package libvuln

import (
	"fmt"
	"regexp"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
)

var ubuntuReleases = []ubuntu.Release{
	ubuntu.Artful,
	ubuntu.Bionic,
	ubuntu.Cosmic,
	ubuntu.Disco,
	ubuntu.Precise,
	ubuntu.Trusty,
	ubuntu.Xenial,
}

var debianReleases = []debian.Release{
	debian.Buster,
	debian.Jessie,
	debian.Stretch,
	debian.Wheezy,
}

var rhelReleases = []rhel.Release{
	rhel.RHEL6,
	rhel.RHEL7,
	rhel.RHEL8,
}

var amazonReleases = []aws.Release{
	aws.Linux1,
	aws.Linux2,
}

var alpineMatrix = map[alpine.Repo][]alpine.Release{
	alpine.Main:      []alpine.Release{alpine.V3_10, alpine.V3_9, alpine.V3_8, alpine.V3_7, alpine.V3_6, alpine.V3_5, alpine.V3_4, alpine.V3_3},
	alpine.Community: []alpine.Release{alpine.V3_10, alpine.V3_9, alpine.V3_8, alpine.V3_7, alpine.V3_6, alpine.V3_5, alpine.V3_4, alpine.V3_3},
}

var suseReleases = []suse.Release{
	suse.Enterprise15,
	suse.Enterprise12,
	suse.EnterpriseServer15,
	suse.EnterpriseServer12,
	suse.EnterpriseServer11,
	suse.EnterpriseDesktop15,
	suse.EnterpriseDesktop12,
	suse.EnterpriseDesktop11,
	suse.Leap423,
	suse.Leap150,
	suse.Leap151,
	suse.OpenStackCloud9,
	suse.OpenStackCloud8,
	suse.OpenStackCloud7,
}

func updaters() ([]driver.Updater, error) {
	updaters := []driver.Updater{}
	for _, rel := range ubuntuReleases {
		updaters = append(updaters, ubuntu.NewUpdater(rel))
	}
	for _, rel := range debianReleases {
		updaters = append(updaters, debian.NewUpdater(rel))
	}
	for _, rel := range amazonReleases {
		up, err := aws.NewUpdater(rel)
		if err != nil {
			return nil, fmt.Errorf("unable to create amazon updater %v: %v", rel, err)
		}
		updaters = append(updaters, up)
	}
	for _, rel := range rhelReleases {
		up, err := rhel.NewUpdater(rel)
		if err != nil {
			return nil, fmt.Errorf("unable to create rhel updater %v: %v", rel, err)
		}
		updaters = append(updaters, up)
	}
	for repo, releases := range alpineMatrix {
		for _, rel := range releases {
			up, err := alpine.NewUpdater(rel, repo)
			if err != nil {
				return nil, fmt.Errorf("unable to create alpine updater %v %v: %v", repo, rel, err)
			}
			updaters = append(updaters, up)
		}
	}

	for year, lim := 2007, time.Now().Year(); year != lim; year++ {
		u, err := oracle.NewUpdater(year)
		if err != nil {
			return nil, fmt.Errorf("unable to create oracle updater: %v", err)
		}
		updaters = append(updaters, u)
	}

	for _, rel := range suseReleases {
		u, err := suse.NewUpdater(rel)
		if err != nil {
			return nil, fmt.Errorf("unable to create suse updater: %v", err)
		}
		updaters = append(updaters, u)
	}

	return updaters, nil
}

func regexFilter(regex string, updaters []driver.Updater) ([]driver.Updater, error) {
	out := []driver.Updater{}
	re, err := regexp.Compile(regex)
	if err != nil {
		return nil, fmt.Errorf("regex failed to compile")
	}
	for _, u := range updaters {
		if re.MatchString(u.Name()) {
			out = append(out, u)
		}
	}
	return out, nil
}
