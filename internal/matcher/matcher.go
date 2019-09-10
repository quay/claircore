package matcher

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

// Matcher is an interface which a Controller uses to query the vulnstore for vulnerabilities.
type Matcher interface {
	// Interested informs the Controller if the implemented Matcher is interested in the provided package.
	Interested(pkg *claircore.Package) bool
	// How informs the Controller how it should match packages with vulnerabilities.
	How() (Matchers []vulnstore.MatchExp)
	// Decide informs the Controller if the given package is affected by the given vulnerability.
	// for example checking the "FixedInVersion" field.
	Decide(pkg *claircore.Package, vuln *claircore.Vulnerability) bool
}
