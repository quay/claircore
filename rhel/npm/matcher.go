package npm

import (
	"context"
	"log/slog"

	"github.com/Masterminds/semver"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher matches npm packages recorded under a Red Hat product CPE.
//
// The vulnerability repository name is a normalized CPE. It must match
// the indexed CPE, including the Red Hat version-stream rule. An empty
// FixedInVersion matches any installed version. An empty installed version
// is not compared when a fix exists. Otherwise the installed semver is
// vulnerable when it is strictly older.
type Matcher struct{}

// Name implements [driver.Matcher].
func (*Matcher) Name() string { return "redhat-npm" }

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == RepositoryKey
}

// Query implements [driver.Matcher].
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryKey}
}

// Vulnerable implements [driver.Matcher].
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.Repo == nil || record.Repository == nil || vuln.Repo.Key != RepositoryKey {
		return false, nil
	}
	var err error
	// Vulnerability repositories do not persist CPE. The name is the normalized form.
	vuln.Repo.CPE, err = cpe.Unbind(vuln.Repo.Name)
	if err != nil {
		slog.WarnContext(ctx, "unable to unbind repo CPE", "reason", err, "vulnerability name", vuln.Name)
		return false, nil
	}
	if !rhel.IsCPESubstringMatch(record.Repository.CPE, vuln.Repo.CPE) {
		return false, nil
	}
	if vuln.FixedInVersion == "" {
		return true, nil
	}
	if record.Package == nil || record.Package.Version == "" {
		slog.WarnContext(ctx, "empty package version", "vulnerability name", vuln.Name)
		return false, nil
	}
	installed, err := semver.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}
	fixed, err := semver.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}
	return installed.Compare(fixed) < 0, nil
}
