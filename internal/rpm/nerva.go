package rpm

import (
	"strings"

	"github.com/quay/claircore"
)

// NERVA returns an rpm NERVA for the package "p", assuming that the
// [Package.Version] is an EVR string. This should hold true for all
// [claircore.Package] instances returned by this package.
func NERVA(p *claircore.Package) string {
	var b strings.Builder
	b.WriteString(p.Name)
	b.WriteByte('-')
	b.WriteString(p.Version)
	b.WriteByte('.')
	b.WriteString(p.Arch)
	return b.String()
}
