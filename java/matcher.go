package java

import (
	"context"
	"fmt"
	"strings"

	version "github.com/masahiro331/go-mvn-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher ...
type Matcher struct{}

// Name implements driver.Matcher.
func (m *Matcher) Name() string { return "java-maven" }

// Filter implements driver.Matcher.
func (matcher *Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository.URI == "https://mvnrepository.com"
}

// Query implements driver.Matcher.
func (matcher *Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName, driver.PackageName}
}

// Vulnerable implements driver.Matcher.
func (matcher *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
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
