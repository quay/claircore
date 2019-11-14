package aws

import (
	"fmt"

	"github.com/quay/claircore"
)

type Release string

const (
	Linux1 Release = "linux1"
	Linux2 Release = "linux2"
	// os-release name ID field consistently available on official amazon linux images
	ID = "amzn"
)

var linux1Dist = &claircore.Distribution{
	Name:       "Amazon Linux AMI",
	DID:        ID,
	Version:    "2018.03",
	VersionID:  "2018.03",
	PrettyName: "Amazon Linux AMI 2018.03",
}

var linux2Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        ID,
	Version:    "2",
	VersionID:  "2",
	PrettyName: "Amazon Linux 2",
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
