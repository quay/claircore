package debian

import (
	"context"

	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher is a [driver.Matcher] for Debian distributions.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "debian-matcher"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == "debian":
		return true
	case record.Distribution.Name == "Debian GNU/Linux":
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
	if vuln.FixedInVersion == "" {
		return true, nil
	}
	// If Debian reports fixed_version is 0,
	// the package is unaffected.
	if vuln.FixedInVersion == "0" {
		return false, nil
	}

	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, nil
	}
	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
