package aws

import (
	version "github.com/knqyf263/go-rpm-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Name() string {
	return "aws-matcher"
}

func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case (record.Distribution.Name == linux1Dist.Name) || (record.Distribution.Name == linux2Dist.Name):
		return true
	case (record.Distribution.DID == ID):
		return true
	}

	return false
}

func (*Matcher) Query() []driver.MatchExp {
	return []driver.MatchExp{
		driver.PackageDistributionVersionID,
	}
}

func (*Matcher) Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool {
	v1 := version.NewVersion(record.Package.Version)
	v2 := version.NewVersion(vuln.FixedInVersion)

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
