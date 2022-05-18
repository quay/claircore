package datastore

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database.
type Updater interface {
	EnrichmentUpdater

	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
	// vulnerabilities, and ensures vulnerabilities from previous updates are
	// not queried by clients.
	UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error)
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
