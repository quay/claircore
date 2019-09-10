package vulnstore

// MatchExp types allow a caller of vulnstore methods to specify how to match
// incoming packages with vulnerabilities. Implementors are tasked with
// how the matching is performed
//
// for example if sql implementation encounters a PackageDistributionDID matcher
// it should create a query similar to "SELECT * FROM vulnerabilities WHERE package_name = ? AND distribution_did = ?"
type MatchExp int

const (
	Unknown MatchExp = iota
	// should match claircore.Package.Source.Name => claircore.Vulnerability.Package.Name
	PackageSourceName
	// should match claircore.Package.Name => claircore.Vulnerability.Package.Name
	PackageName
	// should match claircore.Package.Distribution.DID => claircore.Vulnerability.Package.Distribution.DID
	PackageDistributionDID
	// should match claircore.Package.Distribution.Name => claircore.Vulnerability.Package.Distribution.Name
	PackageDistributionName
	// should match claircore.Package.Distribution.Version => claircore.Vulnerability.Package.Distribution.Version
	PackageDistributionVersion
	// should match claircore.Package.Distribution.VersionCodeName => claircore.Vulnerability.Package.Distribution.VersionCodeName
	PackageDistributionVersionCodeName
	// should match claircore.Package.Distribution.VersionID => claircore.Vulnerability.Package.Distribution.VersionID
	PackageDistributionVersionID
	// should match claircore.Package.Distribution.Arch => claircore.Vulnerability.Package.Distribution.Arch
	PackageDistributionArch
)
