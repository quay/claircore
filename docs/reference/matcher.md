# Matcher
A Matcher performs the heavy lifting of matching manifest contents to relevant vulnerabilities. These implementations provide the smarts for understanding if a particular artifact in a layer is vulnerable to a particular advisory in the database.

```go
package driver

// Matcher is an interface which a Controller uses to query the vulnstore for vulnerabilities.
type Matcher interface {
	// a unique name for the matcher
	Name() string
	// Filter informs the Controller if the implemented Matcher is interested in the provided IndexRecord.
	Filter(record *claircore.IndexRecord) bool
	// Query informs the Controller how it should match packages with vulnerabilities.
	// All conditions are logical AND'd together.
	Query() []MatchConstraint
	// Vulnerable informs the Controller if the given package is affected by the given vulnerability.
	// for example checking the "FixedInVersion" field.
	Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error)
}
```
The `Filter` method is used to inform LibVuln the provided artifact is interesting.
The `Query` method tells LibVuln how to query the security advisory database.
The `Vulnerable` method reports whether the provided package is vulnerable to the provided vulnerability. Typically, this would perform a version check between the artifact and the vulnerability in question.
