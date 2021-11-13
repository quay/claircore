package rhcc

import (
	"context"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var Matcher driver.Matcher = &matcher{}

type matcher struct{}

var _ driver.Matcher = (*matcher)(nil)

func (*matcher) Name() string {
	return "rhel-container-matcher"
}

func (*matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == goldRepo.Name
}

func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

func (*matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	pkgVer, fixedInVer := rpmVersion.NewVersion(record.Package.Version), rpmVersion.NewVersion(vuln.FixedInVersion)
	zlog.Debug(ctx).
		Str("record", record.Package.Version).
		Str("vulnerability", vuln.FixedInVersion).
		Msg("comparing versions")
	return pkgVer.LessThan(fixedInVer), nil
}

// Implement version filtering to have the database only return results for the
// same minor version. Marking the results as not authoritative means the
// Vulnerable method is still called.

func (*matcher) VersionFilter() {}

func (*matcher) VersionAuthoritative() bool { return false }
