package driver

import (
	"encoding/json"
	"time"

	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint string

// Configs is a map of name to ConfigUnmarshaler.
//
// It's used for runtime configuration in the Updater.
type Configs map[string]ConfigUnmarshaler

// EnrichmentRecord is a simple container for JSON enrichment data and the tags
// it will be queried by.
type EnrichmentRecord struct {
	Tags       []string
	Enrichment json.RawMessage
}

// ParsedVulnerabilities is an entity-component system describing discovered
// vulnerabilities.
type ParsedVulnerabilities struct {
	Updater       string
	Vulnerability []Vulnerability
	Package       []Package
	Distribution  []Distribution
	Repository    []Repository
}

// Vulnerability is all per-vulnerability information.
type Vulnerability struct {
	Issued         time.Time
	Name           string
	Description    string
	FixedInVersion string
	Severity       Severity
	Links          []string
	Package        []int // need at least one entry
	Range          types.Range
	ArchOperation  types.ArchOp
	Distribution   int // optional, -1 to omit
	Repository     int // optional, -1 to omit
}

// Severity is severity information
type Severity struct {
	// Upstream should be the value the upstream database provides.
	Upstream string
	// Normalized should be one of the proscribed Severity values. They roughly
	// correlate to CVSSv3 severity levels.
	Normalized types.Severity
}

// Package describes a package.
type Package struct {
	Name              string
	Version           string
	Database          string
	Arch              string
	Module            string
	CPE               cpe.WFN
	NormalizedVersion types.Version
	Kind              types.PackageKind
	Repository        int // optional, -1 to omit
	Source            int // optional, -1 to omit
}

// Distribution describes a distribution.
type Distribution struct {
	ID        string
	VersionID string // Numeric version, like os-release
	Arch      string
	CPE       cpe.WFN
}

// Repository describes a repository.
type Repository struct {
	Name string
	Key  string
	URI  string
	CPE  cpe.WFN
}
