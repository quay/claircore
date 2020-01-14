package driver

import "github.com/quay/claircore"

// MatchConstraint explains to the caller how a search for a package's vulnerability should
// be constrained.
//
// for example if sql implementation encounters a DistributionDID constraint
// it should create a query similar to "SELECT * FROM vulnerabilities WHERE package_name = ? AND distribution_did = ?"
type MatchConstraint int

const (
	_ MatchConstraint = iota
	// should match claircore.Package.Source.Name => claircore.Vulnerability.Package.Name
	PackageSourceName
	// should match claircore.Package.Name => claircore.Vulnerability.Package.Name
	PackageName
	// should match claircore.Package.Distribution.DID => claircore.Vulnerability.Package.Distribution.DID
	DistributionDID
	// should match claircore.Package.Distribution.Name => claircore.Vulnerability.Package.Distribution.Name
	DistributionName
	// should match claircore.Package.Distribution.Version => claircore.Vulnerability.Package.Distribution.Version
	DistributionVersion
	// should match claircore.Package.Distribution.VersionCodeName => claircore.Vulnerability.Package.Distribution.VersionCodeName
	DistributionVersionCodeName
	// should match claircore.Package.Distribution.VersionID => claircore.Vulnerability.Package.Distribution.VersionID
	DistributionVersionID
	// should match claircore.Package.Distribution.Arch => claircore.Vulnerability.Package.Distribution.Arch
	DistributionArch
	// should match claircore.Package.Distribution.CPE => claircore.Vulnerability.Package.Distribution.CPE
	DistributionCPE
	// should match claircore.Package.Distribution.PrettyName => claircore.Vulnerability.Package.Distribution.PrettyName
	DistributionPrettyName
)

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
	Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool
}
