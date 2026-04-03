package oracle

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	OSReleaseID   = "ol"
	OSReleaseName = "Oracle Linux Server"
)

// Matcher is an Oracle Linux matcher.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "oracle"
}

// Filter implements [driver.Matcher].
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
