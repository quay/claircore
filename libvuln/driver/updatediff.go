package driver

import (
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore"
)

// Our diff terminology uses UpdateOpeartion A and UpdateOperation B as arguments.
// A is always the base and B is the update being applied over A.

// UpdateOperation is a unique update to the vulnstore by an Updater.
type UpdateOperation struct {
	Ref         uuid.UUID
	Updater     string
	Fingerprint Fingerprint
	Date        time.Time
}

// UpdateDiff represents added or removed vulnerabilities between update operations
type UpdateDiff struct {
	A       UpdateOperation
	B       UpdateOperation
	Added   []claircore.Vulnerability
	Removed []claircore.Vulnerability
}
