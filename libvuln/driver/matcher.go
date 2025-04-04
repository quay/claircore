package driver

import (
	"context"

	"github.com/quay/claircore"
)

// Matcher is an interface which a Controller uses to query the vulnstore for vulnerabilities.
type Matcher interface {
	// a unique name for the matcher
	Name() string
	// Filter informs the Controller if the implemented Matcher is interested in the provided IndexRecord.
	Filter(record *claircore.IndexRecord) bool
	// Query informs the Controller how it should match packages with vulnerabilities.
	// All conditions are logical AND'd together.
	Query() []claircore.MatchConstraint
	// Vulnerable informs the Controller if the given package is affected by the given vulnerability.
	// for example checking the "FixedInVersion" field.
	Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error)
}

// VersionFilter is an additional interface that a Matcher can implement to
// opt-in to using normalized version information in database queries.
type VersionFilter interface {
	VersionFilter()
	// VersionAuthoritative reports whether the Matcher trusts the database-side
	// filtering to be authoritative.
	//
	// A Matcher may return false if it's using a versioning scheme that can't
	// be completely normalized into a claircore.Version.
	VersionAuthoritative() bool
}
