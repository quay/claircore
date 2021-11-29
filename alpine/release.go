package alpine

import (
	"fmt"

	"github.com/quay/claircore"
)

// Alpine linux has patch releases but their security database
// aggregates security information by major release. We choose
// to normalize detected distributions into major.minor releases and
// parse vulnerabilities into major.minor releases

// Release is a particular release of the Alpine linux distribution
type Release string

// These are known releases.
const (
	V3_15 Release = "v3.15"
	V3_14 Release = "v3.14"
	V3_13 Release = "v3.13"
	V3_12 Release = "v3.12"
	V3_11 Release = "v3.11"
	V3_10 Release = "v3.10"
	V3_9  Release = "v3.9"
	V3_8  Release = "v3.8"
	V3_7  Release = "v3.7"
	V3_6  Release = "v3.6"
	V3_5  Release = "v3.5"
	V3_4  Release = "v3.4"
	V3_3  Release = "v3.3"
)

// Common os-release fields applicable for *claircore.Distribution usage.
const (
	Name = "Alpine Linux"
	ID   = "alpine"
)

func mkdist(maj, min int) *claircore.Distribution {
	return &claircore.Distribution{
		Name:       Name,
		DID:        ID,
		VersionID:  fmt.Sprintf("%d.%d", maj, min),
		PrettyName: fmt.Sprintf("Alpine Linux v%d.%d", maj, min),
	}
}

var (
	alpine3_3Dist  = mkdist(3, 3)
	alpine3_4Dist  = mkdist(3, 4)
	alpine3_5Dist  = mkdist(3, 5)
	alpine3_6Dist  = mkdist(3, 6)
	alpine3_7Dist  = mkdist(3, 7)
	alpine3_8Dist  = mkdist(3, 8)
	alpine3_9Dist  = mkdist(3, 9)
	alpine3_10Dist = mkdist(3, 10)
	alpine3_11Dist = mkdist(3, 11)
	alpine3_12Dist = mkdist(3, 12)
	alpine3_13Dist = mkdist(3, 13)
	alpine3_14Dist = mkdist(3, 14)
	alpine3_15Dist = mkdist(3, 15)
)

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
	case V3_11:
		return alpine3_11Dist
	case V3_12:
		return alpine3_12Dist
	case V3_13:
		return alpine3_13Dist
	case V3_14:
		return alpine3_14Dist
	case V3_15:
		return alpine3_15Dist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
