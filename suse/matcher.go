package suse

import (
	"context"
	"slices"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	OSReleaseIDs   = []string{"sles", "opensuse", "opensuse-leap"}
	OSReleaseNames = []string{"SLES", "openSUSE Leap"}
)

// Matcher implements [driver.Matcher]
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher]
func (*Matcher) Name() string {
	return "suse"
}

// Filter implements [driver.Matcher]
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case slices.Contains(OSReleaseIDs, record.Distribution.DID):
		return true
	case slices.Contains(OSReleaseNames, record.Distribution.Name):
		return true
	default:
		return false
	}
}

// Query implements [driver.Matcher]
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersion,
	}
}

// Vulnerable implements [driver.Matcher]
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	return rpm.MatchVulnerable(ctx, record, vuln)
}
