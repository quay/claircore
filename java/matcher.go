package java

import (
	"context"
	"fmt"
	"github.com/quay/zlog"
	"strings"

	version "github.com/masahiro331/go-mvn-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher is an instance of the java maven matcher. It's exported so it can be used
// in the "defaults" package.
//
// This instance is safe for concurrent use.
var Matcher driver.Matcher = &matcher{}

type matcher struct{}

var _ driver.Matcher = (*matcher)(nil)

// Name implements driver.Matcher.
func (*matcher) Name() string { return "java-maven" }

func (*matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == Repository.Name
}

// Query implements driver.Matcher.
func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

// Vulnerable implements driver.Matcher.
func (*matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	zlog.Debug(ctx).
		Str("record", record.Package.Version).
		Str("vulnerability", vuln.FixedInVersion).
		Msg("comparing versions")
	zlog.Info(ctx).
		Msg(">>>> comparing versions")
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	rv, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}

	a := strings.Split(vuln.FixedInVersion, "+")
	if len(a) > 2 {
		return false, fmt.Errorf("unexpected number of maven versions: %d", len(a))
	}

	v2, err := version.NewVersion(strings.TrimPrefix(a[len(a)-1], "LastAffected:"))
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(a[len(a)-1], "LastAffected:") && rv.GreaterThan(v2) {
		return false, nil
	} else if !strings.HasPrefix(a[len(a)-1], "LastAffected:") && rv.GreaterThanOrEqual(v2) {
		return false, nil
	}

	if len(a)-1 > 0 {
		v1, err := version.NewVersion(a[0])
		if err != nil {
			return false, err
		}
		if rv.LessThan(v1) {
			return false, nil
		}
	}
	return true, nil
}

func (*matcher) VersionFilter() {}

func (*matcher) VersionAuthoritative() bool { return false }
