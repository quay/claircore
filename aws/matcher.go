package aws

import (
	"context"

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

func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionVersionID,
	}
}

func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	v1 := version.NewVersion(record.Package.Version)
	v2 := version.NewVersion(vuln.FixedInVersion)

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	if v2.String() == "0" {
		return true, nil
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
