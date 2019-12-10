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

// Parser is an interface which is embedded into the Updater interface.
//
// Parse should be called with an io.ReadCloser struct where the contents of a security
// advisory databse can be read and parsed into an array of *claircore.Vulnerability
type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}

// Fetcher is an interface which is embedded into the Updater interface.
//
// When called the interface should determine if new security advisory data is available.
// Fingerprint may be passed into in order for the Fetcher to determine if the contents has changed
//
// If there is new content Fetcher should return a io.ReadCloser where the new content can be read.
// Optionally a fingerprint can be returned which uniqeually identifies the new content.
//
// If the conent has not change an  Unchanged error should be returned.
type Fetcher interface {
	Fetch(context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
}

// Unchanged is returned by Fetchers when the database has not changed.
var Unchanged = errors.New("database contents unchanged")

// Fingerprint is some identifiying information about a vulnerability database.
type Fingerprint string
