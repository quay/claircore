package vulnstore

import (
	"context"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database.
type Updater interface {
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
	GetUpdateOperations(context.Context, ...string) (map[string][]driver.UpdateOperation, error)

	// GetLatestUpdateRefs reports the latest update reference for every known
	// updater.
	GetLatestUpdateRefs(context.Context) (map[string]uuid.UUID, error)
	// GetLatestUpdateRef reports the latest update reference of any known
	// updater.
	GetLatestUpdateRef(context.Context) (uuid.UUID, error)
	// DeleteUpdateOperations removes an UpdateOperation.
	DeleteUpdateOperations(context.Context, ...uuid.UUID) error
	// GetUpdateOperationDiff reports the UpdateDiff of the two referenced
	// Operations.
	//
	// In diff(1) terms, this is like
	//
	//	diff prev cur
	//
	GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)
}
