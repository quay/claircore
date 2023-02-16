package gobin

import (
	"context"

	"github.com/Masterminds/semver"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/updater/osv"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher ...
type Matcher struct{}

// Name implements driver.Matcher.
func (m *Matcher) Name() string { return "gobin" }

// Filter implements driver.Matcher.
func (matcher *Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository.URI == "https://pkg.go.dev/"
}

// Query implements driver.Matcher.
func (matcher *Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName, driver.PackageName}
}

// Vulnerable implements driver.Matcher.
func (matcher *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	sv, err := semver.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}
	v := osv.FromSemver(sv)
	return vuln.Range.Contains(&v), nil
}
