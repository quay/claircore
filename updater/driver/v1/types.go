package driver

import (
	"encoding/json"
	"time"

	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint string

// Configs ...
type Configs map[string]ConfigUnmarshaler

// UpdaterSet ...
type UpdaterSet map[string]Updater

// EnrichmentRecord is a simple container for JSON enrichment data and the tags
// it will be queried by.
type EnrichmentRecord struct {
	Tags       []string
	Enrichment json.RawMessage
}

type ParsedVulnerabilities struct {
	Updater       string
	Vulnerability []Vulnerability
	Package       []Package
	Distribution  []Distribution
	Repository    []Repository
}

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

type Severity struct {
	Upstream   string
	Normalized types.Severity
}

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

type Distribution struct {
	ID        string
	VersionID string // Numeric version, like os-release
	Arch      string
	CPE       cpe.WFN
}

type Repository struct {
	Name string
	Key  string
	URI  string
	CPE  cpe.WFN
}
