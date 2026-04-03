package aws

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
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
	case (record.Distribution.Name == AL1Dist.Name):
		return true
	case (record.Distribution.Name == AL2Dist.Name):
		return true
	case (record.Distribution.Name == AL2023Dist.Name):
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
	return rpm.MatchVulnerable(ctx, record, vuln)
}
