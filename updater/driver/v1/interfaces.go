package driver

import (
	"archive/zip"
	"context"
	"errors"
	"io/fs"
	"net/http"
)

// ErrUnchanged is returned by Fetchers when the database has not changed.
var ErrUnchanged = errors.New("driver: database contents unchanged")

// ConfigUnmarshaler can be thought of as an Unmarshal function with the byte
// slice provided, or a Decode function.
//
// The function should populate a passed struct with any configuration
// information.
type ConfigUnmarshaler func(interface{}) error

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
	ParseVulnerability(context.Context, fs.FS) (*ParsedVulnerabilities, error)
}

// EnrichmentParser ...
type EnrichmentParser interface {
	ParseEnrichment(context.Context, fs.FS) ([]EnrichmentRecord, error)
}
