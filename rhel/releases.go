package rhel

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

// RHEL has minor releases however their security database files are bundled together
// by major version. for example `com.redhat.rhsa-RHEL7.xml`
// we choose to normalize detected distributions into major releases and parse vulnerabilities by major release versions.

type Release int

const (
	RHEL3 Release = 3
	RHEL4 Release = 4
	RHEL5 Release = 5
	RHEL6 Release = 6
	RHEL7 Release = 7
	RHEL8 Release = 8
)

var rhel3Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "3",
	VersionID:  "3",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 3",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:3"),
}
var rhel4Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "4",
	VersionID:  "4",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 4",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:4"),
}
var rhel5Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "5",
	VersionID:  "5",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 5",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:5"),
}
var rhel6Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "6",
	VersionID:  "6",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 6",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6"),
}
var rhel7Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "7",
	VersionID:  "7",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 7",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7"),
}
var rhel8Dist = &claircore.Distribution{
	Name:       "Red Hat Enterprise Linux Server",
	Version:    "8",
	VersionID:  "8",
	DID:        "rhel",
	PrettyName: "Red Hat Enterprise Linux Server 8",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8"),
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case RHEL3:
		return rhel3Dist
	case RHEL4:
		return rhel4Dist
	case RHEL5:
		return rhel5Dist
	case RHEL6:
		return rhel6Dist
	case RHEL7:
		return rhel7Dist
	case RHEL8:
		return rhel8Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
