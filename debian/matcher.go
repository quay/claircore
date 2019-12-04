package debian

import (
	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Name() string {
	return "debian-matcher"
}

func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == OSReleaseID:
		return true
	case record.Distribution.Name == OSReleaseName:
		return true
	default:
		return false
	}
}

func (*Matcher) Query() []driver.MatchExp {
	return []driver.MatchExp{
		driver.PackageDistributionVersion,
	}
}

func (*Matcher) Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool {
	v1, err := version.NewVersion(record.Package.Version)
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
