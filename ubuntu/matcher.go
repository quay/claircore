package ubuntu

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	version "github.com/knqyf263/go-deb-version"
)

var _ driver.Matcher = (*Matcher)(nil)

type Matcher struct{}

func (*Matcher) Filter(record *claircore.ScanRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == "ubuntu":
		return true
	case record.Distribution.Name == "Ubuntu":
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

func (*Matcher) Vulnerable(record *claircore.ScanRecord, vuln *claircore.Vulnerability) bool {
	if vuln.FixedInVersion == "" {
		return true
	}

	v1, _ := version.NewVersion(record.Package.Version)
	v2, _ := version.NewVersion(vuln.FixedInVersion)
	if v1.LessThan(v2) {
		return true
	}

	return false
}
