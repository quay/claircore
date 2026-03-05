package rhcc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Matcher is an instance of the rhcc matcher. It's exported so it can be used
// in the "defaults" package.
//
// This instance is safe for concurrent use.
var Matcher driver.Matcher = &matcher{}

type matcher struct{}

var _ driver.Matcher = (*matcher)(nil)

// Name implements [driver.Matcher].
func (*matcher) Name() string { return "rhel-container-matcher" }

// Filter implements [driver.Matcher].
func (*matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Key == RepositoryKey
}

// Query implements [driver.Matcher].
func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryKey}
}

// Vulnerable implements [driver.Matcher].
func (*matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	var err error
	if record.Repository.Name != GoldRepo.Name {
		// This is not a gold repo record, so we need to check if the CPE matches.
		vuln.Repo.CPE, err = cpe.Unbind(vuln.Repo.Name)
		if err != nil {
			slog.WarnContext(ctx, "unable to unbind repo CPE", "reason", err, "vulnerability name", vuln.Name)
			return false, nil
		}
		if !cpe.Compare(vuln.Repo.CPE, record.Repository.CPE).IsSuperset() && !rhel.IsCPESubstringMatch(record.Repository.CPE, vuln.Repo.CPE) {
			return false, nil
		}
	}

	slog.DebugContext(ctx, "comparing versions", "record", record.Package.Version, "vulnerability", vuln.FixedInVersion)
	pkgVer, err := rpmver.Parse(record.Package.Version)
	if err != nil {
		return false, fmt.Errorf("rhcc: unable to parse version %q: %w", record.Package.Version, err)
	}
	fixedVer, err := rpmver.Parse(vuln.FixedInVersion)
	if err != nil {
		return false, fmt.Errorf("rhcc: unable to parse version %q: %w", vuln.FixedInVersion, err)
	}
	return rpmver.Compare(&pkgVer, &fixedVer) == -1, nil
}

// Implement version filtering to have the database only return results for the
// same minor version. Marking the results as not authoritative means the
// Vulnerable method is still called.

func (*matcher) VersionFilter() {}

func (*matcher) VersionAuthoritative() bool { return false }
