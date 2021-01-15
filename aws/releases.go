package aws

import (
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

type Release string

const (
	Linux1 Release = "linux1"
	Linux2 Release = "linux2"
	// os-release name ID field consistently available on official amazon linux images
	ID = "amzn"
)

func (r Release) mirrorlist() string {
	switch r {
	case Linux1:
		return "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	case Linux2:
		return "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	}
	panic(fmt.Sprintf("unknown release %q", r))
}

var linux1Dist = &claircore.Distribution{
	Name:       "Amazon Linux AMI",
	DID:        ID,
	Version:    "2018.03",
	VersionID:  "2018.03",
	PrettyName: "Amazon Linux AMI 2018.03",
	CPE:        cpe.MustUnbind("cpe:/o:amazon:linux:2018.03:ga"),
}

var linux2Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        ID,
	Version:    "2",
	VersionID:  "2",
	PrettyName: "Amazon Linux 2",
	CPE:        cpe.MustUnbind("cpe:2.3:o:amazon:amazon_linux:2"),
}

func releaseToDist(release Release) *claircore.Distribution {
	switch release {
	case Linux1:
		return linux1Dist
	case Linux2:
		return linux2Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
