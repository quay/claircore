package ubuntu

import (
	"context"

	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher is a [driver.Matcher] for Ubuntu distributions.
type Matcher struct{}

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "ubuntu-matcher"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
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

// Query implements [driver.Matcher].
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersionID,
	}
}

// Vulnerable implements [driver.Matcher].
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}

	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	if v2.String() == "0" {
		return true, nil
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
