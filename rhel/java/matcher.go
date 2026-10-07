// Package java matches Java packages recorded under a Red Hat product CPE.
package java

import (
	"context"
	"log/slog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/maven"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// RedHatMatcher matches Java packages recorded under a Red Hat product CPE.
type RedHatMatcher struct{}

var _ driver.Matcher = (*RedHatMatcher)(nil)

// Name implements [driver.Matcher].
func (*RedHatMatcher) Name() string { return "redhat-java" }

// Filter implements [driver.Matcher].
func (*RedHatMatcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == RepositoryKey
}

// Query implements [driver.Matcher].
func (*RedHatMatcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryKey}
}

// Vulnerable implements [driver.Matcher].
//
// The vulnerability repository name is a normalized CPE. It must match
// the indexed CPE, including the Red Hat version-stream rule. An empty
// FixedInVersion matches any installed version. An empty installed version
// is not compared when a fix exists: a Maven null version is older than
// every real fix. Otherwise the installed Maven version is vulnerable when
// it is strictly older.
func (*RedHatMatcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
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
	// An empty version parses as a Maven null version, which compares older
	// than every real fix. There is no installed version to compare.
	if record.Package == nil || record.Package.Version == "" {
		slog.WarnContext(ctx, "empty package version", "vulnerability name", vuln.Name)
		return false, nil
	}
	installed, err := maven.ParseVersion(record.Package.Version)
	if err != nil {
		return false, err
	}
	fixed, err := maven.ParseVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}
	return installed.Compare(fixed) < 0, nil
}
