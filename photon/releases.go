package photon

import "github.com/quay/claircore"

// Release indicates the Photon release OVAL database to pull from.
type Release string

// These are some known Releases.
const (
	Photon1 Release = `photon1`
	Photon2 Release = `photon2`
	Photon3 Release = `photon3`
)

var photon1Dist = &claircore.Distribution{
	Name:       "VMware Photon OS",
	Version:    "1.0",
	VersionID:  "1.0",
	PrettyName: "VMware Photon OS/Linux",
	DID:        "photon",
}

var photon2Dist = &claircore.Distribution{
	Name:       "VMware Photon OS",
	Version:    "2.0",
	VersionID:  "2.0",
	PrettyName: "VMware Photon OS/Linux",
	DID:        "photon",
}

var photon3Dist = &claircore.Distribution{
	Name:       "VMware Photon OS",
	Version:    "3.0",
	VersionID:  "3.0",
	PrettyName: "VMware Photon OS/Linux",
	DID:        "photon",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case Photon1:
		return photon1Dist
	case Photon2:
		return photon2Dist
	case Photon3:
		return photon3Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
