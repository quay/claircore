package alpine

import "github.com/quay/claircore"

// Alpine linux has patch releases but their security database
// aggregates security information by major release. We choose
// to normalize detected distributions into major.minor releases and
// parse vulnerabilities into major.minor releases

// Release is a particular release of the Alpine linux distribution
type Release string

const (
	V3_10 Release = "v3.10"
	V3_9  Release = "v3.9"
	V3_8  Release = "v3.8"
	V3_7  Release = "v3.7"
	V3_6  Release = "v3.6"
	V3_5  Release = "v3.5"
	V3_4  Release = "v3.4"
	V3_3  Release = "v3.3"
)

// ReleaseToPrettyName maps a Release to the PrettyName found in alpine's os-release file.
//
// Official Alpine images consistantly have a Pretty_Name field in their os-release files.
var ReleaseToPrettyName = map[Release]string{
	V3_10: "Alpine Linux v3.10",
	V3_9:  "Alpine Linux v3.9",
	V3_8:  "Alpine Linux v3.8",
	V3_7:  "Alpine Linux v3.7",
	V3_6:  "Alpine Linux v3.6",
	V3_5:  "Alpine Linux v3.5",
	V3_4:  "Alpine Linux v3.4",
	V3_3:  "Alpine Linux v3.3",
}

// Common os-release fields applicable for *claircore.Distribution usage.
const (
	Name = "Alpine Linux"
	ID   = "alpine"
)

var alpine3_3Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.3",
	PrettyName: "Alpine Linux v3.3",
}

var alpine3_4Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.4",
	PrettyName: "Alpine Linux v3.4",
}

var alpine3_5Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.5",
	PrettyName: "Alpine Linux v3.5",
}

var alpine3_6Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.6",
	PrettyName: "Alpine Linux v3.6",
}

var alpine3_7Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.7",
	PrettyName: "Alpine Linux v3.7",
}

var alpine3_8Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.8",
	PrettyName: "Alpine Linux v3.8",
}

var alpine3_9Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.9",
	PrettyName: "Alpine Linux v3.9",
}

var alpine3_10Dist = &claircore.Distribution{
	Name:       "Alpine Linux",
	DID:        "alpine",
	VersionID:  "3.10",
	PrettyName: "Alpine Linux v3.10",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case V3_3:
		return alpine3_3Dist
	case V3_4:
		return alpine3_4Dist
	case V3_5:
		return alpine3_5Dist
	case V3_6:
		return alpine3_6Dist
	case V3_7:
		return alpine3_7Dist
	case V3_8:
		return alpine3_8Dist
	case V3_9:
		return alpine3_9Dist
	case V3_10:
		return alpine3_10Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
