package chainguard

import (
	"context"

	version "github.com/knqyf263/go-apk-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	ChainguardMatcher = &matcher{"chainguard"}
	WolfiMatcher      = &matcher{"wolfi"}
)

var _ driver.Matcher = (*matcher)(nil)

// Matcher implements driver.Matcher for Chainguard and Wolfi containers.
type matcher struct {
	name string
}

// Name implements driver.Matcher.
func (m *matcher) Name() string {
	return m.name + "-matcher"
}

// Filter implements driver.Matcher.
func (m *matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == m.name:
		return true
	case record.Distribution.Name == m.name:
		return true
	default:
		return false
	}
}

// Query implements driver.Matcher.
func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionPrettyName,
	}
}

// Vulnerable implements driver.Matcher.
func (*matcher) Vulnerable(_ context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	// Version "0" tracks false-positives, and it indicates the package is not affected by the vulnerability.
	// See the following for more information:
	// https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/scanning_implementation.md#the-meaning-of-version-0
	if vuln.FixedInVersion == "0" {
		return false, nil
	}

	pkgVersion, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, nil
	}

	fixedInVersion, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, nil
	}

	if pkgVersion.LessThan(fixedInVersion) {
		return true, nil
	}

	return false, nil
}
