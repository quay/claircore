package gobin

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.VersionFilter = (*Matcher)(nil)
)

// Matcher matches discovered go packages against advisories provided via OSV.
type Matcher struct{}

// Name implements driver.Matcher.
func (m *Matcher) Name() string { return "gobin" }

// Filter implements driver.Matcher.
func (matcher *Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil &&
		record.Repository.URI == "https://pkg.go.dev/"
}

// Query implements driver.Matcher.
func (matcher *Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

// Vulnerable implements driver.Matcher.
func (matcher *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// no-op
	return false, nil
}

func (matcher *Matcher) VersionFilter()             {}
func (matcher *Matcher) VersionAuthoritative() bool { return true }
