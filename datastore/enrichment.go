package datastore

import (
	"context"

	"github.com/google/uuid"

	"github.com/quay/claircore/libvuln/driver"
)

// EnrichmentIter is an [Iter] of enrichment records.
type EnrichmentIter Iter[*driver.EnrichmentRecord]

// EnrichmentUpdater is an interface exporting the necessary methods
// for storing and querying Enrichments.
type EnrichmentUpdater interface {
	// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the provided
	// EnrichmentRecord(s), and ensures enrichments from previous updates are not
	// queries by clients.
	UpdateEnrichments(ctx context.Context, kind string, fingerprint driver.Fingerprint, enrichments []driver.EnrichmentRecord) (uuid.UUID, error)
	// UpdateEnrichmentsIter performs the same operation as UpdateEnrichments, but
	// accepting an iterator function.
	UpdateEnrichmentsIter(ctx context.Context, kind string, fingerprint driver.Fingerprint, enIter EnrichmentIter) (uuid.UUID, error)
}

// Enrichment is an interface for querying enrichments from the store.
type Enrichment interface {
	GetEnrichment(ctx context.Context, kind string, tags []string) ([]driver.EnrichmentRecord, error)
}
