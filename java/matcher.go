package java

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

type matcher struct{}

var (
	// Matcher implements driver.Matcher for java packages using a maven version comparison.
	Matcher *matcher

	_ driver.Matcher = (*matcher)(nil)
)

func (*matcher) Name() string {
	return "java-maven"
}

func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

func (*matcher) Vulnerable(ctx context.Context, r *claircore.IndexRecord, v *claircore.Vulnerability) (bool, error) {
	zlog.Debug(ctx).
		Str("record", r.Package.Version).
		Str("vulnerability", v.FixedInVersion).
		Msg("comparing versions")
	pv, err := parseMavenVersion(r.Package.Version)
	if err != nil {
		return false, fmt.Errorf("java-maven: martian package version: %w", err)
	}
	fv, err := parseMavenVersion(v.FixedInVersion) // I don't think this is right...
	if err != nil {
		return false, fmt.Errorf("java-maven: martian fix version: %w", err)
	}
	return pv.Compare(fv) < 0, nil
}

func (*matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == Repository.Name
}
