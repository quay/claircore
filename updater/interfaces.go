package updater

import (
	"context"

	"github.com/google/uuid"

	driver "github.com/quay/claircore/updater/driver/v1"
)

type Store interface {
	// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the
	// provided EnrichmentRecord(s), and ensures enrichments from previous
	// updates are not queries by clients.
	UpdateEnrichments(ctx context.Context, ref uuid.UUID, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) error

	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
	// vulnerabilities, and ensures vulnerabilities from previous updates are
	// not queried by clients.
	UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs *driver.ParsedVulnerabilities) error

	GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error)
}

type Locker interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
}
