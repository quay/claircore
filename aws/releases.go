package aws

import (
	"fmt"

	"github.com/quay/claircore"
)

type Release string

const (
	Linux1 Release = "linux1"
	Linux2 Release = "linux2"
)

// ReleaseToVersion maps a Release to the Version found in Amazon Linux's os-release file
//
// Official Amazon Linux images consistently have a Version field in their os-release file
var ReleaseToVersion = map[Release]string{
	// currently alas is only publishing security data for 2018.03 linux 1 releases
	Linux1: "2018.03",
	Linux2: "2",
}

var linux2Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        "amzn",
	Version:    "2",
	VersionID:  "2",
	PrettyName: "Amazon Linux 2",
}

var linux1Dist = &claircore.Distribution{
	Name:       "Amazon Linux AMI",
	DID:        "amzn",
	Version:    "2018.03",
	VersionID:  "2018.03",
	PrettyName: "Amazon Linux AMI 2018.03",
}

func releaseToDist(release Release) (*claircore.Distribution, error) {
	switch release {
	case Linux1:
		return linux1Dist, nil
	case Linux2:
		return linux2Dist, nil
	default:
		return nil, fmt.Errorf("unknown release")
	}
}
