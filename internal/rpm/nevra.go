package rpm

import (
	"github.com/quay/claircore"
)

// NEVRA returns an rpm NEVRA for the package "p", assuming that the
// [Package.Version] is an EVR string. This should hold true for all
// [claircore.Package] instances returned by this package.
func NEVRA(p *claircore.Package) string {
	return p.Name + "-" + p.Version + "." + p.Arch
}
