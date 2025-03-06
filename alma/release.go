package alma

import (
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// RelMap memoizes the Distributions handed out by this package.
//
// Doing this is a cop-out to the previous approach of having a hard-coded set of structs.
// In the case something is (mistakenly) doing pointer comparisons, this will make that work
// but still allows us to have the list of distributions grow ad-hoc.
var relMap sync.Map

func mkRelease(r string) *claircore.Distribution {
	v, ok := relMap.Load(r)
	if !ok {
		v, _ = relMap.LoadOrStore(r, &claircore.Distribution{
			Name:       "AlmaLinux",
			Version:    r,
			VersionID:  r,
			DID:        "alma",
			PrettyName: "AlmaLinux " + r,
			CPE:        cpe.MustUnbind("cpe:/o:almalinux:almalinux:" + r),
		})
	}
	return v.(*claircore.Distribution)
}
