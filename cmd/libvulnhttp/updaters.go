package main

import (
	"fmt"
	"regexp"

	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/ubuntu"
	"github.com/rs/zerolog/log"
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
			return nil, fmt.Errorf("unable to create amazon updater: %v", err)
		}
		updaters = append(updaters, up)
	}

	if u, err := oracle.NewUpdater(oracle.WithLogger(&log.Logger)); err != nil {
		return nil, fmt.Errorf("unable to create oracle updater: %v", err)
	} else {
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
