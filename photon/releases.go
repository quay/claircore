package photon

import (
	"sync"

	"github.com/quay/claircore"
)

// Release indicates the Photon release OVAL database to pull from.
type Release string

var distCache sync.Map // key: version string (e.g., "1.0"), value: *claircore.Distribution

func mkDist(ver string) *claircore.Distribution {
	v, _ := distCache.LoadOrStore(ver, &claircore.Distribution{
		Name:       "VMware Photon OS",
		Version:    ver,
		VersionID:  ver,
		PrettyName: "VMware Photon OS/Linux",
		DID:        "photon",
	})
	return v.(*claircore.Distribution)
}
