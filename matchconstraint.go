package claircore

// MatchConstraint explains to the caller how a search for a package's vulnerability should
// be constrained.
//
// for example if sql implementation encounters a DistributionDID constraint
// it should create a query similar to "SELECT * FROM vulnerabilities WHERE package_name = ? AND distribution_did = ?"
type MatchConstraint int

//go:generate go run golang.org/x/tools/cmd/stringer -type MatchConstraint

const (
	_ MatchConstraint = iota
	// should match claircore.Package.Source.Name => claircore.Vulnerability.Package.Name
	PackageSourceName
	// should match claircore.Package.Name => claircore.Vulnerability.Package.Name
	PackageName
	// should match claircore.Package.Module => claircore.Vulnerability.Package.Module
	PackageModule
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
	// should match claircore.Package.Repository.Name => claircore.Vulnerability.Package.Repository.Name
	RepositoryName
	// should match claircore.Package.Repository.Key => claircore.Vulnerability.Package.Repository.Key
	RepositoryKey
	// should match claircore.Vulnerability.FixedInVersion != ""
	HasFixedInVersion
)
