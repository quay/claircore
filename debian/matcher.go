package debian

import (
	version "github.com/knqyf263/go-deb-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Filter(pkg *claircore.Package) bool {
	if pkg.Dist == nil {
		return false
	}

	switch {
	case pkg.Dist.DID == OSReleaseID:
		return true
	case pkg.Dist.Name == OSReleaseName:
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
	v1, err := version.NewVersion(pkg.Version)
	if err != nil {
		return false
	}

	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false
	}

	if vuln.FixedInVersion == "" {
		return true
	}

	if v2.String() == "0" {
		return true
	}

	if v1.LessThan(v2) {
		return true
	}

	return false
}
