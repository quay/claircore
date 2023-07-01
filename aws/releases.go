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
	Linux2023 Release = "linux2023"
	// os-release name ID field consistently available on official amazon linux images
	ID = "amzn"
)

func (r Release) mirrorlist() string {
	//doc:url updater
	const (
		l1 = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
		l2 = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
		l2023 = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"
	)
	switch r {
	case Linux1:
		return l1
	case Linux2:
		return l2
	case Linux2023:
		return l2023
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

var linux2023Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        ID,
	Version:    "2023",
	VersionID:  "2023",
	PrettyName: "Amazon Linux 2023",
	CPE:        cpe.MustUnbind("cpe:2.3:o:amazon:amazon_linux:2023"),
}


func releaseToDist(release Release) *claircore.Distribution {
	switch release {
	case Linux1:
		return linux1Dist
	case Linux2:
		return linux2Dist
	case Linux2023:
		return linux2023Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
