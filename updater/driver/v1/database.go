package driver

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// These need to exist in some common place, so they're tucked here.

type UpdateKind string

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

var ErrDuplicateRef = errors.New("an UpdateOperation with that ref already exists")
