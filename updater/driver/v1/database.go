package driver

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// These need to exist in some common place, so they're tucked here.

// UpdateKind is used to tag the kind of update being handled.
type UpdateKind string

// Known update kinds.
const (
	VulnerabilityKind UpdateKind = "vulnerability"
	EnrichmentKind    UpdateKind = "enrichment"
)

// UpdateOperation is a unique update to the Store by an Updater.
type UpdateOperation struct {
	Date        time.Time
	Updater     string
	Kind        UpdateKind
	Fingerprint Fingerprint
	Ref         uuid.UUID
}

// UpdateDiff represents added or removed vulnerabilities between update
// operations.
type UpdateDiff struct {
	Added, Removed []Vulnerability
	Prev, Cur      UpdateOperation
}

// ErrDuplicateRef is reported when a ref is attempted to be created when it
// already exists.
var ErrDuplicateRef = errors.New("an UpdateOperation with that ref already exists")
