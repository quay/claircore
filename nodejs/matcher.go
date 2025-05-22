package nodejs

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.VersionFilter = (*Matcher)(nil)
)

// Matcher attempts to correlate discovered nodejs packages with reported vulnerabilities.
type Matcher struct{}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "nodejs" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Name == repository
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(_ context.Context, _ *claircore.IndexRecord, _ *claircore.Vulnerability) (bool, error) {
	// no-op
	return false, nil
}

func (*Matcher) VersionFilter()             {}
func (*Matcher) VersionAuthoritative() bool { return true }
