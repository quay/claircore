package datastore

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Type aliases from old names to the current.
//
// These can be removed if we're okay with breaking the API.
type (
	// MatcherStore is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1] name.
	MatcherStore = MatcherV1
	// Updater is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1Updater] name.
	Updater = MatcherV1Updater
	// Vulnerability is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1Vulnerability] name.
	Vulnerability = MatcherV1Vulnerability
	// EnrichmentUpdater is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1EnrichmentUpdater] name.
	EnrichmentUpdater = MatcherV1EnrichmentUpdater
	// Enrichment is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1Enrichment] name.
	Enrichment = MatcherV1Enrichment
	// GetOpts is an alias from the previous name to the current.
	//
	// Deprecated: Callers should use the [MatcherV1VulnerabilityGetOpts] name.
	GetOpts = MatcherV1VulnerabilityGetOpts
)

// MatcherV1 aggregates all interface types
type MatcherV1 interface {
	MatcherV1Updater
	MatcherV1Vulnerability
	MatcherV1Enrichment
}

// MatcherV1EnrichmentUpdater is an interface exporting the necessary methods
// for storing and querying Enrichments.
type MatcherV1EnrichmentUpdater interface {
	// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the provided
	// EnrichmentRecord(s), and ensures enrichments from previous updates are not
	// queries by clients.
	UpdateEnrichments(ctx context.Context, kind string, fingerprint driver.Fingerprint, enrichments []driver.EnrichmentRecord) (uuid.UUID, error)
}

// MatcherV1Enrichment is an interface for querying enrichments from the store.
type MatcherV1Enrichment interface {
	GetEnrichment(ctx context.Context, kind string, tags []string) ([]driver.EnrichmentRecord, error)
}

// MatcherV1Updater is an interface exporting the necessary methods
// for updating a vulnerability database.
type MatcherV1Updater interface {
	MatcherV1EnrichmentUpdater

	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
	// vulnerabilities, and ensures vulnerabilities from previous updates are
	// not queried by clients.
	UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error)
	// DeltaUpdateVulnerabilities creates a new UpdateOperation consisting of existing
	// vulnerabilities and new vulnerabilities. It also takes an array of deleted
	// vulnerability names which should no longer be available to query.
	DeltaUpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability, deletedVulns []string) (uuid.UUID, error)
	// GetUpdateOperations returns a list of UpdateOperations in date descending
	// order for the given updaters.
	//
	// The returned map is keyed by Updater implementation's unique names.
	//
	// If no updaters are specified, all UpdateOperations are returned.
	GetUpdateOperations(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error)
	// GetLatestUpdateRefs reports the latest update reference for every known
	// updater.
	GetLatestUpdateRefs(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error)
	// GetLatestUpdateRef reports the latest update reference of any known
	// updater.
	GetLatestUpdateRef(context.Context, driver.UpdateKind) (uuid.UUID, error)
	// DeleteUpdateOperations removes an UpdateOperation.
	// A call to GC must be run after this to garbage collect vulnerabilities associated
	// with the UpdateOperation.
	//
	// The number of UpdateOperations deleted is returned.
	DeleteUpdateOperations(context.Context, ...uuid.UUID) (int64, error)
	// GetUpdateOperationDiff reports the UpdateDiff of the two referenced
	// Operations.
	//
	// In diff(1) terms, this is like
	//
	//	diff prev cur
	//
	GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)
	// GC will delete any update operations for an updater which exceeds the provided keep
	// value.
	//
	// Implementations may throttle the GC process for datastore efficiency reasons.
	//
	// The returned int64 value indicates the remaining number of update operations needing GC.
	// Running this method till the returned value is 0 accomplishes a full GC of the vulnstore.
	GC(ctx context.Context, keep int) (int64, error)
	// Initialized reports whether the vulnstore contains vulnerabilities.
	Initialized(context.Context) (bool, error)
	// RecordUpdaterStatus records that an updater is up to date with vulnerabilities at this time
	RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error
	// RecordUpdaterSetStatus records that all updaters from an updater set are up to date with vulnerabilities at this time
	RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) error
}

// MatcherV1VulnerabilityGetOpts provides instructions on how to match packages to vulnerabilities.
type MatcherV1VulnerabilityGetOpts struct {
	// Matchers tells the Get method to limit the returned vulnerabilities by
	// the provided [driver.MatchConstraint]s.
	Matchers []driver.MatchConstraint
	// Debug asks the database layer to log extra information.
	//
	// Deprecated: This does nothing.
	Debug bool
	// VersionFiltering enables filtering based on the normalized versions in
	// the database.
	VersionFiltering bool
}

// MatcherV1Vulnerability is the interface for querying stored Vulnerabilities.
type MatcherV1Vulnerability interface {
	// Get finds the vulnerabilities which match each package provided in the
	// [IndexRecord]s. This may be a one-to-many relationship. A map of Package
	// ID to Vulnerabilities is returned.
	Get(ctx context.Context, records []*claircore.IndexRecord, opts MatcherV1VulnerabilityGetOpts) (map[string][]*claircore.Vulnerability, error)
}
