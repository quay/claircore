package ubuntu

type Release string

const (
	Artful  Release = "artful"
	Bionic  Release = "bionic"
	Cosmic  Release = "cosmic"
	Disco   Release = "disco"
	Precise Release = "precise"
	Trusty  Release = "trusty"
	Xenial  Release = "xenial"
)

var AllReleases = map[Release]struct{}{
	Artful:  struct{}{},
	Bionic:  struct{}{},
	Cosmic:  struct{}{},
	Disco:   struct{}{},
	Precise: struct{}{},
	Trusty:  struct{}{},
	Xenial:  struct{}{},
}
