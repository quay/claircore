package debian

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
