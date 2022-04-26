package ubuntu

import (
	"github.com/quay/claircore"
)

type Release string

const (
	Artful  Release = "artful" // deprecated
	Bionic  Release = "bionic"
	Cosmic  Release = "cosmic"
	Disco   Release = "disco"
	Precise Release = "precise" // deprecated
	Trusty  Release = "trusty"
	Xenial  Release = "xenial"
	Eoan    Release = "eoan"
	Focal   Release = "focal"
	Impish  Release = "impish"
)

var AllReleases = map[Release]struct{}{
	Artful:  struct{}{},
	Bionic:  struct{}{},
	Cosmic:  struct{}{},
	Disco:   struct{}{},
	Precise: struct{}{},
	Trusty:  struct{}{},
	Xenial:  struct{}{},
	Eoan:    struct{}{},
	Focal:   struct{}{},
	Impish:  struct{}{},
}

var ReleaseToVersionID = map[Release]string{
	Artful:  "17.10",
	Bionic:  "18.04",
	Cosmic:  "18.10",
	Disco:   "19.04",
	Precise: "12.04",
	Trusty:  "14.04",
	Xenial:  "16.04",
	Eoan:    "19.10",
	Focal:   "20.04",
	Impish:  "21.10",
}

var artfulDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "17.10 (Artful Aardvark)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 17.10",
	VersionID:       "17.10",
	VersionCodeName: "artful",
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

var preciseDist = &claircore.Distribution{
	Name:       "Ubuntu",
	Version:    "12.04.5 LTS, Precise Pangolin",
	DID:        "ubuntu",
	VersionID:  "12.04",
	PrettyName: "Ubuntu precise (12.04.5 LTS)",
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
	Version:         "16.04.6 LTS (Xenial Xerus)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 16.04.6 LTS",
	VersionID:       "16.04",
	VersionCodeName: "xenial",
}

var eoanDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "19.10 (Eoan Ermine)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 19.10",
	VersionID:       "19.10",
	VersionCodeName: "eoan",
}

var focalDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "20.04 LTS (Focal Fossa)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 20.04 LTS",
	VersionID:       "20.04",
	VersionCodeName: "focal",
}

var impishDist = &claircore.Distribution{
	Name:            "Ubuntu",
	Version:         "21.10 (Impish Indri)",
	DID:             "ubuntu",
	PrettyName:      "Ubuntu 21.10",
	VersionID:       "21.10",
	VersionCodeName: "impish",
}

func releaseToDist(r Release) *claircore.Distribution {
	switch r {
	case Artful:
		return artfulDist
	case Bionic:
		return bionicDist
	case Cosmic:
		return cosmicDist
	case Disco:
		return discoDist
	case Precise:
		return preciseDist
	case Trusty:
		return trustyDist
	case Xenial:
		return xenialDist
	case Eoan:
		return eoanDist
	case Focal:
		return focalDist
	case Impish:
		return impishDist
	default:
		// return empty dist
		return &claircore.Distribution{}
	}
}
