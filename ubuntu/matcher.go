package ubuntu

import (
	version "github.com/knqyf263/go-deb-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

type Matcher struct{}

func (*Matcher) Interested(pkg *claircore.Package) bool {
	if pkg.Dist == nil {
		return false
	}

	switch {
	case pkg.Dist.DID == "ubuntu":
		return true
	case pkg.Dist.Name == "Ubuntu":
		return true
	default:
		return false
	}
}

func (*Matcher) How() []vulnstore.MatchExp {
	return []vulnstore.MatchExp{
		vulnstore.PackageDistributionVersionCodeName,
	}
}

func (*Matcher) Decide(pkg *claircore.Package, vuln *claircore.Vulnerability) bool {
	if vuln.FixedInVersion == "" {
		return true
	}

	v1, _ := version.NewVersion(pkg.Version)
	v2, _ := version.NewVersion(vuln.FixedInVersion)
	if v1.LessThan(v2) {
		return true
	}

	return false
}
