package rhel

import (
	"context"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Matcher implements [driver.Matcher].
type Matcher struct {
	ignoreUnpatched bool
}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "rhel"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == repositoryKey
}

// Query implements [driver.Matcher].
func (m *Matcher) Query() []driver.MatchConstraint {
	mcs := []driver.MatchConstraint{driver.PackageModule, driver.RepositoryKey}
	if m.ignoreUnpatched {
		mcs = append(mcs, driver.HasFixedInVersion)
	}
	return mcs
}

// IsCPESubstringMatch is a Red Hat specific hack that handles the "CPE
// patterns" in the VEX data. For historical/unfathomable reasons, Red Hat
// doesn't use the syntax defined in the Matching Expression spec. For example,
// "cpe:/a:redhat:openshift:4" is expected to match
// "cpe:/a:redhat:openshift:4.13::el8".
//
// This is defined (citation needed) to be a substring match on the "pattern"
// and "target" CPEs. Since we always normalize CPEs into v2.3 "Formatted
// String" form, we need to trim the added "ANY" attributes from the pattern.
//
// TODO(crozzy) Remove once RH VEX data updates CPEs with standard matching
// expressions.
func IsCPESubstringMatch(recordCPE cpe.WFN, vulnCPE cpe.WFN) bool {
	return strings.HasPrefix(recordCPE.String(), strings.TrimRight(vulnCPE.String(), ":*"))
}

// Vulnerable implements [driver.Matcher].
//
// Vulnerable will interpret the [claircore.Vulnerability].Repo.CPE as a CPE
// match expression, and to be considered vulnerable, the relationship between
// [claircore.IndexRecord].Repository.CPE and the
// [claircore.Vulnerability].Repo.CPE needs to be a CPE Name Comparison Relation
// of SUPERSET(⊇)(Source is a superset or equal to the target).
//
// See: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf Section 6.2.
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.Repo == nil || record.Repository == nil || vuln.Repo.Key != repositoryKey {
		return false, nil
	}
	var err error
	// This conversion has to be done because our current data model doesn't
	// support the claircore.Vulnerability.Repo.CPE field.
	vuln.Repo.CPE, err = cpe.Unbind(vuln.Repo.Name)
	if err != nil {
		zlog.Warn(ctx).
			Str("vulnerability name", vuln.Name).
			Err(err).
			Msg("unable to unbind repo CPE")
		return false, nil
	}
	if !cpe.Compare(vuln.Repo.CPE, record.Repository.CPE).IsSuperset() && !IsCPESubstringMatch(record.Repository.CPE, vuln.Repo.CPE) {
		return false, nil
	}

	// TODO(hank) Switch to the [rpmver] package.
	pkgVer := version.NewVersion(record.Package.Version)
	var vulnVer version.Version
	// Assume the vulnerability record we have is for the last known vulnerable
	// version, so greater versions aren't vulnerable.
	cmp := func(i int) bool { return i != version.GREATER }
	// But if it's explicitly marked as a fixed-in version, it's only vulnerable
	// if less than that version.
	if vuln.FixedInVersion != "" {
		vulnVer = version.NewVersion(vuln.FixedInVersion)
		cmp = func(i int) bool { return i == version.LESS }
	} else {
		// If a vulnerability doesn't have FixedInVersion, assume it is unfixed.
		vulnVer = version.NewVersion("65535:0")
	}
	// compare version and architecture
	return cmp(pkgVer.Compare(vulnVer)) && vuln.ArchOperation.Cmp(record.Package.Arch, vuln.Package.Arch), nil
}
