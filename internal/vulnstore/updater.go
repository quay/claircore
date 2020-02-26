package vulnstore

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database
type Updater interface {
	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided vulnerabilities, and ensures vulnerabilities from previous updates
	// are not queried by clients.
	UpdateVulnerabilities(ctx context.Context, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error
	// GetUpdateOperations returns a list of UpdateOperations in date descending order for the given updaters.
	// Returned map is keyed by Updater implementations unique names.
	// If updater slice is nil or empty all UpdateOperations are returned.
	GetUpdateOperations(ctx context.Context, updaters []string) (map[string][]*driver.UpdateOperation, error)
	// DeleteUpdateOperations removes an UpdateOperation and the associated vulnerabilities from the vulnstore.
	DeleteUpdateOperations(ctx context.Context, UOIDs []string) error
	// GetUpdateOperationDiff returns the vulnerabilities added and removed when UpdaterOperation B is applied to UpdateOperation A.
	// Implementations decide if appling diffs between non-sequential updates is an error.
	GetUpdateOperationDiff(ctx context.Context, UOID_A, UOID_B string) (*driver.UpdateDiff, error)
}
