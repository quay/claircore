package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type matcher struct{}

var (
	_ driver.Matcher = (*matcher)(nil)
)

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
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	rv, err := parseMavenVersion(record.Package.Version)
	if err != nil {
		return false, err
	}
	a := strings.Split(vuln.FixedInVersion, "+")
	if len(a) > 2 {
		return false, fmt.Errorf("unexpected number of maven versions: %d", len(a))
	}

	v2, err := parseMavenVersion(strings.TrimPrefix(a[len(a)-1], "LastAffected:"))
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(a[len(a)-1], "LastAffected:") && rv.Compare(v2) > 0 {
		return false, nil
	} else if !strings.HasPrefix(a[len(a)-1], "LastAffected:") && rv.Compare(v2) >= 0 {
		return false, nil
	}

	if len(a)-1 > 0 {
		v1, err := parseMavenVersion(a[0])
		if err != nil {
			return false, err
		}
		if rv.Compare(v1) < 0 {
			return false, nil
		}
	}
	return true, nil
}
