package driver

import (
	"context"
	"errors"
	"io"

	"github.com/quay/claircore"
)

// MatchExp types allow a caller of vulnstore methods to specify how to match
// incoming packages with vulnerabilities. Implementors are tasked with
// how the matching is performed
//
// for example if sql implementation encounters a PackageDistributionDID matcher
// it should create a query similar to "SELECT * FROM vulnerabilities WHERE package_name = ? AND distribution_did = ?"
type MatchExp int

const (
	_ MatchExp = iota
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
	Query() []MatchExp
	// Vulnerable informs the Controller if the given package is affected by the given vulnerability.
	// for example checking the "FixedInVersion" field.
	Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool
}

// Updater is an aggregate interface combining the method set of a Fetcher and a Parser
// and forces a Name() to be provided
type Updater interface {
	Name() string
	Fetcher
	Parser
}

// Parser is an interface when called with an io.ReadCloser should parse
// the provided contents and return a list of *claircore.Vulnerabilities
type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}

// Fetcher is an interface which is embedded into the Updater struct.
// When called the implementaiton should return an io.ReadCloser with
// contents of the target vulnerability data
type Fetcher interface {
	// Fetch should retrieve the target vulnerability data and return an io.ReadCloser
	// with the contents. Fetch should also return a string which can used to determine
	// if these contents should be applied to the vulnerability database. for example
	// a sha265 sum of a OVAL xml file.
	Fetch() (io.ReadCloser, string, error)
}

// FetcherNG is an experimental fetcher interface.
//
// This may go away or be renamed without warning.
type FetcherNG interface {
	FetchContext(context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
}

// Unchanged is returned by Fetchers when the database has not changed.
var Unchanged = errors.New("database contents unchanged")

// Fingerprint is some identifiying information about a vulnerability database.
type Fingerprint string
