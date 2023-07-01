package aws

import (
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

type Release string

const (
	AmazonLinux1 Release = "AL1"
	AmazonLinux2 Release = "AL2"
	AmazonLinux2023 Release = "AL2023"
	// os-release name ID field consistently available on official amazon linux images
	ID = "amzn"
)

func (r Release) mirrorlist() string {
	//doc:url updater
	const (
		al1 = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
		al2 = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
		al2023 = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"
	)
	switch r {
	case AmazonLinux1:
		return al1
	case AmazonLinux2:
		return al2
	case AmazonLinux2023:
		return al2023
	}
	panic(fmt.Sprintf("unknown release %q", r))
}

var AL1Dist = &claircore.Distribution{
	Name:       "Amazon Linux AMI",
	DID:        ID,
	Version:    "2018.03",
	VersionID:  "2018.03",
	PrettyName: "Amazon Linux AMI 2018.03",
	CPE:        cpe.MustUnbind("cpe:/o:amazon:linux:2018.03:ga"),
}

var AL2Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        ID,
	Version:    "2",
	VersionID:  "2",
	PrettyName: "Amazon Linux 2",
	CPE:        cpe.MustUnbind("cpe:2.3:o:amazon:amazon_linux:2"),
}

var AL2023Dist = &claircore.Distribution{
	Name:       "Amazon Linux",
	DID:        ID,
	Version:    "2023",
	VersionID:  "2023",
	PrettyName: "Amazon Linux 2023",
	CPE:        cpe.MustUnbind("cpe:2.3:o:amazon:amazon_linux:2023"),
}


func releaseToDist(release Release) *claircore.Distribution {
	switch release {
	case AmazonLinux1:
		return AL1Dist
	case AmazonLinux2:
		return AL2Dist
	case AmazonLinux2023:
		return AL2023Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
