package test

import (
	"fmt"
	"strconv"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

func WFN(i int) cpe.WFN {
	r := cpe.WFN{}
	for i := 0; i < cpe.NumAttr; i++ {
		r.Attr[i].Kind = cpe.ValueAny
	}
	var err error
	if r.Attr[cpe.Part], err = cpe.NewValue("o"); err != nil {
		panic(err)
	}
	if r.Attr[cpe.Vendor], err = cpe.NewValue("projectquay"); err != nil {
		panic(err)
	}
	if r.Attr[cpe.Product], err = cpe.NewValue(`clair\.test`); err != nil {
		panic(err)
	}
	if r.Attr[cpe.Version], err = cpe.NewValue(strconv.Itoa(i)); err != nil {
		panic(err)
	}
	if err := r.Valid(); err != nil {
		panic(err)
	}
	return r
}

// GenUniqueDistributions creates an array of unique distributions. the array is guaranteed not to have
// any duplicately named dist fields.
func GenUniqueDistributions(n int) []*claircore.Distribution {
	dists := []*claircore.Distribution{}
	for i := 0; i < n; i++ {
		dists = append(dists, &claircore.Distribution{
			ID:              strconv.Itoa(i),
			Name:            fmt.Sprintf("distribution-%d", i),
			Version:         fmt.Sprintf("version-%d", i),
			VersionCodeName: fmt.Sprintf("version-code-name-%d", i),
			DID:             fmt.Sprintf("did-%d", i),
			VersionID:       fmt.Sprintf("version-id-%d", i),
			Arch:            fmt.Sprintf("arch-%d", i),
			CPE:             WFN(i),
			PrettyName:      fmt.Sprintf("pretty-name-%d", i),
		})
	}
	return dists
}
