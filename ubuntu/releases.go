package ubuntu

import (
	"github.com/quay/claircore"
)

type Release string

const (
	Bionic Release = "bionic"
	Cosmic Release = "cosmic"
	Disco  Release = "disco"
	Trusty Release = "trusty"
	Xenial Release = "xenial"
)

var AllReleases = map[Release]struct{}{
	Bionic: struct{}{},
	Cosmic: struct{}{},
	Disco:  struct{}{},
	Trusty: struct{}{},
	Xenial: struct{}{},
}
var ReleaseToVersionID = map[Release]string{
	Bionic: "18.04",
	Cosmic: "18.10",
	Disco:  "19.04",
	Trusty: "14.04",
	Xenial: "16.04",
}

var bionicDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "18.04.3 LTS (Bionic Beaver)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 18.04.3 LTS",
	VersionID:       "18.04",
	VersionCodeName: "bionic",
}

var cosmicDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "18.10 (Cosmic Cuttlefish)",
	DID:             "ubuntu",
	VersionID:       "18.10",
	VersionCodeName: "cosmic",
	PrettyName:      "Ubuntu 18.10",
}

var discoDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "19.04 (Disco Dingo)",
	DID:             "ubuntu",
	VersionID:       "19.04",
	VersionCodeName: "disco",
	PrettyName:      "Ubuntu 19.04",
}

var trustyDist = &claircore.Distribution{
	Name:       "Ubuntu",
	Version:    "14.04.6 LTS, Trusty Tahr",
	DID:        "ubuntu",
	PrettyName: "Ubuntu 14.04.6 LTS",
	VersionID:  "14.04",
}

var xenialDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "14.04.6 LTS, Trusty Tahr",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 16.04.6 LTS",
	VersionID:       "16.04",
	VersionCodeName: "xenial",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case Bionic:
		return bionicDist
	case Cosmic:
		return bionicDist
	case Disco:
		return discoDist
	case Trusty:
		return trustyDist
	case Xenial:
		return xenialDist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
