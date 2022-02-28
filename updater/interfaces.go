package updater

import (
	"context"

	"github.com/google/uuid"

	driver "github.com/quay/claircore/updater/driver/v1"
)

// Store is the common interface to a data store that Updater expects.
type Store interface {
	// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the
	// provided EnrichmentRecord(s), and ensures enrichments from previous
	// updates are not queries by clients.
	UpdateEnrichments(ctx context.Context, ref uuid.UUID, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) error

	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
	// vulnerabilities, and ensures vulnerabilities from previous updates are
	// not queried by clients.
	UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs *driver.ParsedVulnerabilities) error

	// GetLatestUpdateOperations reports the latest update operations. It must
	// report at least one per updater, if it exists.
	GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error)
}

// Locker is the Context-based locking Updater expects.
type Locker interface {
	// TryLock returns a cancelled Context if it would need to wait to acquire
	// the named lock.
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	// Lock waits to acquire the named lock. The returned Context may be
	// cancelled if the process loses confidence that the lock is valid.
	Lock(context.Context, string) (context.Context, context.CancelFunc)
}
