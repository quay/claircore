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
	GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error)
	// DeleteUpdateOperations removes an UpdateOperation and allows associated
	// vulnerabilities to be garbage collected.
	DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) error
	// GetUpdateOperationDiff returns the vulnerabilities added and removed when
	// UpdaterOperation B is applied to UpdateOperation A.
	//
	// Implementations decide if requesting diffs between non-sequential updates
	// is an error.
	GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error)
}
