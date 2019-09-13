package ubuntu

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	version "github.com/knqyf263/go-deb-version"
)

var _ driver.Matcher = (*Matcher)(nil)

type Matcher struct{}

func (*Matcher) Filter(pkg *claircore.Package) bool {
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

func (*Matcher) Query() []driver.MatchExp {
	return []driver.MatchExp{
		driver.PackageDistributionVersionCodeName,
	}
}

func (*Matcher) Vulnerable(pkg *claircore.Package, vuln *claircore.Vulnerability) bool {
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
