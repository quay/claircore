# VersionFilter
VersionFilter is an additional interface a Matcher may implement.
If implemented, LibVuln will attempt to use the database and the normalized version field of a package
to filter vulnerabilities in the database. 
This is an opt-in optimization for when a package manager's version scheme can be normalized into a claircore.Version. 

```go
package driver

// VersionFilter is an additional interface that a Matcher can implment to
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
```
