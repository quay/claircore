package test

import (
	"fmt"

	"github.com/quay/claircore"
)

// GenUniqueDistributions creates an array of unique distributions. the array is guaranteed not to have
// any duplicately named dist fields.
func GenUniqueDistributions(n int) []*claircore.Distribution {
	dists := []*claircore.Distribution{}
	for i := 0; i < n; i++ {
		dists = append(dists, &claircore.Distribution{
			ID:              i,
			Name:            fmt.Sprintf("distribution-%d", i),
			Version:         fmt.Sprintf("version-%d", i),
			VersionCodeName: fmt.Sprintf("version-code-name-%d", i),
			DID:             fmt.Sprintf("did-%d", i),
			VersionID:       fmt.Sprintf("version-id-%d", i),
			Arch:            fmt.Sprintf("arch-%d", i),
			CPE:             fmt.Sprintf("cpe-%d", i),
		})
	}
	return dists
}
