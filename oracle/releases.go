package oracle

import "github.com/quay/claircore"

// Oracle Linux has minor releases such as 7.7 and 6.10
// however their elsa OVAL xml sec db always references the major release
// for example: <platform>Oracle Linux 5</platform>
// for this reason the oracle distribution scanner will detect and normalize
// minor releases to major releases to match vulnerabilities correctly

type Release string

const (
	Eight Release = "8"
	Seven Release = "7"
	Six   Release = "6"
	Five  Release = "5"
)

var eightDist = &claircore.Distribution{
	Name:            "Oracle Linux Server",
	Version:         "8",
	DID:             "ol",
	PrettyName:      "Oracle Linux Server 8",
	VersionID:       "8",
	VersionCodeName: "Oracle Linux 8",
}

var sevenDist = &claircore.Distribution{
	Name:            "Oracle Linux Server",
	Version:         "7",
	DID:             "ol",
	PrettyName:      "Oracle Linux Server 7",
	VersionID:       "7",
	VersionCodeName: "Oracle Linux 7",
}

var sixDist = &claircore.Distribution{
	Name:            "Oracle Linux Server",
	Version:         "6",
	DID:             "ol",
	PrettyName:      "Oracle Linux Server 6",
	VersionID:       "6",
	VersionCodeName: "Oracle Linux 6",
}

var fiveDist = &claircore.Distribution{
	Name:            "Oracle Linux Server",
	Version:         "5",
	DID:             "ol",
	PrettyName:      "Oracle Linux Server 5",
	VersionID:       "5",
	VersionCodeName: "Oracle Linux 5",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case Eight:
		return eightDist
	case Seven:
		return sevenDist
	case Six:
		return sixDist
	case Five:
		return fiveDist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
