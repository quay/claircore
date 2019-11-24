package debian

import "github.com/quay/claircore"

type Release string

const (
	Buster  Release = "buster"
	Jessie  Release = "jessie"
	Stretch Release = "stretch"
	Wheezy  Release = "wheezy"
)

var AllReleases = map[Release]struct{}{
	Buster:  struct{}{},
	Jessie:  struct{}{},
	Stretch: struct{}{},
	Wheezy:  struct{}{},
}

var ReleaseToVersionID = map[Release]string{
	Buster:  "10",
	Jessie:  "8",
	Stretch: "9",
	Wheezy:  "7",
}

var busterDist = &claircore.Distribution{
	PrettyName:      "Debian GNU/Linux 10 (buster)",
	Name:            "Debian GNU/Linux",
	VersionID:       "10",
	Version:         "10 (buster)",
	VersionCodeName: "buster",
	DID:             "debian",
}

var jessieDist = &claircore.Distribution{
	PrettyName: "Debian GNU/Linux 8 (jessie)",
	Name:       "Debian GNU/Linux",
	VersionID:  "8",
	Version:    "8 (jessie)",
	DID:        "debian",
}

var stretchDist = &claircore.Distribution{
	PrettyName:      "Debian GNU/Linux 9 (stretch)",
	Name:            "Debian GNU/Linux",
	VersionID:       "9",
	Version:         "9 (stretch)",
	VersionCodeName: "stretch",
	DID:             "debian",
}

var wheezyDist = &claircore.Distribution{
	PrettyName: "Debian GNU/Linux 7 (wheezy)",
	Name:       "Debian GNU/Linux",
	VersionID:  "7",
	Version:    "7 (wheezy)",
	DID:        "debian",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case Buster:
		return busterDist
	case Jessie:
		return jessieDist
	case Stretch:
		return stretchDist
	case Wheezy:
		return wheezyDist
	default:
		return &claircore.Distribution{}
	}
}
