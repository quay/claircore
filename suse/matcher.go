package suse

import (
	"context"

	version "github.com/knqyf263/go-rpm-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	OSReleaseIDs   = []string{"sles", "opensuse", "opensuse-leap"}
	OSReleaseNames = []string{"SLES", "openSUSE Leap"}
)

// Matcher implements driver.Matcher
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements driver.Matcher
func (*Matcher) Name() string {
	return "suse"
}

// Filter implements driver.Matcher
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case contains(OSReleaseIDs, record.Distribution.DID):
		return true
	case contains(OSReleaseNames, record.Distribution.Name):
		return true
	default:
		return false
	}
}

// Query implements driver.Matcher
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersion,
	}
}

// Vulnerable implements driver.Matcher
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
	return cmp(pkgVer.Compare(vulnVer)) && vuln.ArchOperation.Cmp(record.Package.Arch, vuln.Package.Arch), nil
}

// contains is a helper function to see if a slice of strings contains a specific string
func contains(opts []string, s string) bool {

	// Iterate through list
	for _, opt := range opts {

		// If found
		if opt == s {
			return true
		}
	}
	// Not found
	return false
}
