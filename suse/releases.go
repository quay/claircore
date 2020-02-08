package suse

import "github.com/quay/claircore"

// Suse has service pack releases however their security database files are bundled together
// by major version. for example `SUSE Linux Enterprise Server 15 (all Service Packs) - suse.linux.enterprise.server.15.xml`
// we choose to normalize detected distributions into major releases and parse vulnerabilities by major release versions.

// Release indicates the SUSE release OVAL database to pull from.
type Release string

// These are some known Releases.
const (
	EnterpriseServer15 Release = `suse.linux.enterprise.server.15`
	EnterpriseServer12 Release = `suse.linux.enterprise.server.12`
	EnterpriseServer11 Release = `suse.linux.enterprise.server.11`
	Leap151            Release = `opensuse.leap.15.1`
	Leap150            Release = `opensuse.leap.15.0`
	Leap423            Release = `opensuse.leap.42.3`
)

var enterpriseServer15Dist = &claircore.Distribution{
	Name:       "SLES",
	Version:    "15",
	VersionID:  "15",
	PrettyName: "SUSE Linux Enterprise Server 15",
	DID:        "sles",
}

var enterpriseServer12Dist = &claircore.Distribution{
	Name:       "SLES",
	Version:    "12",
	VersionID:  "12",
	PrettyName: "SUSE Linux Enterprise Server 12",
	DID:        "sles",
}

var enterpriseServer11Dist = &claircore.Distribution{
	Name:       "SLES",
	Version:    "11",
	VersionID:  "11",
	PrettyName: "SUSE Linux Enterprise Server 11",
	DID:        "sles",
}

var leap151Dist = &claircore.Distribution{
	Name:       "openSUSE Leap",
	Version:    "15.1",
	DID:        "opensuse-leap",
	VersionID:  "15.1",
	PrettyName: "openSUSE Leap 15.1",
}

var leap15Dist = &claircore.Distribution{
	Name:       "openSUSE Leap",
	Version:    "15.0",
	DID:        "opensuse-leap",
	VersionID:  "15.0",
	PrettyName: "openSUSE Leap 15.0",
}

var leap423Dist = &claircore.Distribution{
	Name:       "openSUSE Leap",
	Version:    "42.3",
	DID:        "opensuse",
	VersionID:  "42.3",
	PrettyName: "openSUSE Leap 42.3",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case EnterpriseServer15:
		return enterpriseServer15Dist
	case EnterpriseServer12:
		return enterpriseServer12Dist
	case EnterpriseServer11:
		return enterpriseServer11Dist
	case Leap150:
		return leap15Dist
	case Leap151:
		return leap151Dist
	case Leap423:
		return leap423Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
