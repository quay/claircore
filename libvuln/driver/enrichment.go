package driver

import (
	"context"
	"encoding/json"
	"io"

	"github.com/quay/claircore"
)

// EnrichmentRecord is a simple container for JSON enrichment data
// and the tags it will be queried by.
type EnrichmentRecord struct {
	Tags       []string
	Enrichment json.RawMessage
}

// This EnrichmentRecord is basically using json.RawMessage to represent "Any"
// in a way that will be able to be queried if needed in the future.

// EnrichmentUpdater fetches an Enrichment data source, parses its contents,
// and returns individual EnrichmentRecords.
type EnrichmentUpdater interface {
	// Name is a unique name for this updater.
	//
	// The name preferably indicates the vendor who implemented it and the
	// enrichment data source it's fetching and interpreting.
	// This must be paired with an Enricher using the same value.
	Name() string
	// FetchEnrichment should use the provided Fingerprint to determine if
	// there's new data to download, and if so return it in an io.ReadCloser and
	// a new Fingerprint.
	//
	// If there's no new data, the method should report Unchanged.
	FetchEnrichment(context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
	// ParseEnrichment reads from the provided io.ReadCloser, parses its contents,
	// and returns a slice of EnrichmentRecords or an error.
	ParseEnrichment(context.Context, io.ReadCloser) ([]EnrichmentRecord, error)
}

// NoopUpdater is designed to be embedded into other Updater types so they can
// be used in the original updater machinery.
//
// This may go away if the Updater interface becomes Vulnerability agnostic
// in the future.
type NoopUpdater struct{}

// Fetch implements Updater.
func (u NoopUpdater) Fetch(_ context.Context, _ Fingerprint) (io.ReadCloser, Fingerprint, error) {
	return (*nilRC)(nil), "", nil
}

// Parse implements Updater.
func (u NoopUpdater) Parse(_ context.Context, _ io.ReadCloser) ([]*claircore.Vulnerability, error) {
	return []*claircore.Vulnerability{}, nil
}

// NilRC is a type whose nil pointer implements io.ReadCloser.
type nilRC struct{}

func (*nilRC) Close() error               { return nil }
func (*nilRC) Read(_ []byte) (int, error) { return 0, io.EOF }

// EnrichmentGetter is a handle to obtain Enrichments with a given tag.
//
// The implementation provided to an Enricher will make use of the Enricher's
// name to scope down results.
type EnrichmentGetter interface {
	GetEnrichment(context.Context, []string) ([]EnrichmentRecord, error)
}

// Enricher is the interface for enriching a vulnerability report.
//
// Enrichers are called after the VulnerabilityReport is constructed.
type Enricher interface {
	// Name is a unique name for this Enricher.
	//
	// The name preferably indicates the vendor who implemented it and matches
	// the corresponding EnrichmentUpdater.
	Name() string
	// Enrich extracts a set of tags from the provided VulnerabilityReport and utilizes
	// the provided EnrichmentGetter to retrieve any Enrichments associated with the query tags.
	//
	// Enrichers may not modify the passed VulnerabilityReport. Doing so may
	// panic the program.
	//
	// The implemented Enricher returns JSON blobs of Enrichment data and a key
	// explaining to the client how to interpret the data.
	Enrich(context.Context, EnrichmentGetter, *claircore.VulnerabilityReport) (string, []json.RawMessage, error)
}
