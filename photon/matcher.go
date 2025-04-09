package photon

import (
	"context"

	version "github.com/knqyf263/go-rpm-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher implements driver.Matcher.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements driver.Matcher.
func (*Matcher) Name() string {
	return "photon"
}

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Distribution != nil &&
		record.Distribution.DID == "photon"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersion,
	}
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	pkgVer, vulnVer := version.NewVersion(record.Package.Version), version.NewVersion(vuln.Package.Version)
	// Assume the vulnerability record we have is for the last known vulnerable
	// version, so greater versions aren't vulnerable.
	cmp := func(i int) bool { return i != version.GREATER }
	// But if it's explicitly marked as a fixed-in version, it't only vulnerable
	// if less than that version.
	if vuln.FixedInVersion != "" {
		vulnVer = version.NewVersion(vuln.FixedInVersion)
		cmp = func(i int) bool { return i == version.LESS }
	}
	return cmp(pkgVer.Compare(vulnVer)), nil
}
