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

// UpdaterFactory is called to construct new Updaters.
type UpdaterFactory interface {
	// Name is used to determine what configuration to use when calling Create.
	Name() string
	// Create is called whenever Updaters are needed to run.
	//
	// The Updater runner makes no assumptions about the lifecycle of the
	// updaters, so implementations may construct new objects on every call, or
	// create a set once and return it repeatedly.
	Create(context.Context, ConfigUnmarshaler) ([]Updater, error)
}

// Updater is the interface for fetching security advisory information.
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
	// Fetch
	//
	// When called, the function should determine if new security advisory data
	// is available. A Fingerprint may be passed into in order for the Fetcher to
	// determine if the content has changed.
	//
	// If it has, the entirety of the database should be written to the provided
	// zip.Writer.
	//
	// If the content has not changed, ErrUnchanged should be returned.
	Fetch(context.Context, *zip.Writer, Fingerprint, *http.Client) (Fingerprint, error)
}

// VulnerabilityParser takes a provided fs and reports the Vulnerabilites
// found.
//
// The returned ParsedVulnerabilites object may have its "Updater" member
// changed to match the value reported by the Name method.
type VulnerabilityParser interface {
	ParseVulnerability(context.Context, fs.FS) (*ParsedVulnerabilities, error)
}

// EnrichmentParser takes a provided fs and reports the Enrichments found.
type EnrichmentParser interface {
	ParseEnrichment(context.Context, fs.FS) ([]EnrichmentRecord, error)
}
