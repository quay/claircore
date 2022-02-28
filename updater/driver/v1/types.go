package driver

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
)

// ErrUnchanged is returned by Fetchers when the database has not changed.
var ErrUnchanged = errors.New("driver: database contents unchanged")

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint string

// ConfigUnmarshaler can be thought of as an Unmarshal function with the byte
// slice provided, or a Decode function.
//
// The function should populate a passed struct with any configuration
// information.
type ConfigUnmarshaler func(interface{}) error

// Configs ...
type Configs map[string]ConfigUnmarshaler

// UpdaterSet ...
type UpdaterSet map[string]Updater

// UpdaterFactory ...
type UpdaterFactory interface {
	Name() string
	Create(context.Context, ConfigUnmarshaler) (UpdaterSet, error)
}

// Updater ...
//
// An Updater should implement at least one of the Parser interfaces.
type Updater interface {
	// Name is a unique name for this updater.
	//
	// The name preferably indicates the vendor who implemented it and the data
	// source it's fetching and interpreting.
	//
	// For Enrichers, this must be paired with an Enricher using the same value.
	Name() string
	// Fetch ...
	//
	// When called the function should determine if new security advisory data is available.
	// Fingerprint may be passed into in order for the Fetcher to determine if the contents has changed
	//
	// If the content has not changed, ErrUnchanged should be returned.
	Fetch(context.Context, *zip.Writer, Fingerprint, *http.Client) (Fingerprint, error)
}

// VulnerabilityParser ...
type VulnerabilityParser interface {
	ParseVulnerability(context.Context, fs.FS) ([]claircore.Vulnerability, error)
}

// EnrichmentParser ...
type EnrichmentParser interface {
	ParseEnrichment(context.Context, fs.FS) ([]EnrichmentRecord, error)
}

// EnrichmentRecord is a simple container for JSON enrichment data and the tags
// it will be queried by.
type EnrichmentRecord struct {
	Tags       []string
	Enrichment json.RawMessage
}

// UpdateKind ...
type UpdateKind string

const (
	VulnerabilityKind UpdateKind = "vulnerability"
	EnrichmentKind    UpdateKind = "enrichment"
)

// UpdateOperation is a unique update to the Store by an Updater.
type UpdateOperation struct {
	Updater     string
	Fingerprint Fingerprint
	Kind        UpdateKind
	Date        time.Time
	Ref         uuid.UUID
}

// UpdateDiff represents added or removed vulnerabilities between update operations
type UpdateDiff struct {
	Added, Removed []claircore.Vulnerability
	Prev, Cur      UpdateOperation
}
