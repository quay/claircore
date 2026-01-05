package photon

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher implements [driver.Matcher].
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "photon"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Distribution != nil &&
		record.Distribution.DID == "photon"
}

// Query implements [driver.Matcher].
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersion,
	}
}

// Vulnerable implements [driver.Matcher].
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	return rpm.MatchVulnerable(ctx, record, vuln)
}
