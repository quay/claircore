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
	Ref         uuid.UUID   `json:"ref"`
	Updater     string      `json:"updater"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Date        time.Time   `json:"date"`
}

// UpdateDiff represents added or removed vulnerabilities between update operations
type UpdateDiff struct {
	Prev    UpdateOperation           `json:"prev"`
	Cur     UpdateOperation           `json:"cur"`
	Added   []claircore.Vulnerability `json:"added"`
	Removed []claircore.Vulnerability `json:"removed"`
}
