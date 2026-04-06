// Package fixtures provides definitions and helpers for working with
// claircore testing fixtures.
package fixtures

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"iter"
	"regexp"
	"strings"
)

// These are the known media types.
const (
	MediaTypeVEX      = `application/csaf+json`
	MediaTypeManifest = `application/vnd.com.redhat.container.acceptancetest.v1+csv`
	MediaTypeBOM      = `application/spdx+json`
)

// These are the compressed variants of the known media types
const (
	MediaTypeZstdVEX      = `application/csaf+json+zstd`
	MediaTypeZstdManifest = `application/vnd.com.redhat.container.acceptancetest.v1+csv+zstd`
	MediaTypeZstdBOM      = `application/spdx+json+zstd`
)

// ParseManifest parses a vulnerability manifest from the given reader.
// The media type must be one of [MediaTypeManifest] or [MediaTypeZstdManifest].
func ParseManifest(ctx context.Context, mt string, rd io.Reader) (iter.Seq2[ManifestRecord, error], error) {
	mr := csv.NewReader(bufio.NewReader(rd))
	mr.ReuseRecord = true
	mr.Comment = '#'
	switch mt {
	case MediaTypeManifest, MediaTypeZstdManifest:
		mr.FieldsPerRecord = 3
	default:
		return nil, fmt.Errorf("fixtures: unknown media type %q", mt)
	}

	seq := func(yield func(ManifestRecord, error) bool) {
		for {
			var m ManifestRecord
			s, err := mr.Read()
			switch {
			case err == nil:
			case errors.Is(err, io.EOF):
				return
			default:
				err := fmt.Errorf("fixtures: error at position %d: %w", mr.InputOffset(), err)
				yield(m, err)
				return
			}

			if !trackingID.MatchString(s[0]) {
				l, c := mr.FieldPos(0)
				err := fmt.Errorf("fixtures: invalid tracking ID at line %d, column %d", l, c)
				yield(m, err)
				return
			}
			m.ID = s[0]

			if len(s[1]) == 0 {
				l, c := mr.FieldPos(1)
				err := fmt.Errorf("fixtures: invalid product ID at line %d, column %d", l, c)
				yield(m, err)
				return
			}
			m.Product = s[1]

			switch strings.ToUpper(s[2]) {
			case StatusAffected.String():
				m.Status = StatusAffected
			case StatusNotAffected.String():
				m.Status = StatusNotAffected
			case StatusAbsent.String():
				m.Status = StatusAbsent
			default:
				l, c := mr.FieldPos(2)
				err := fmt.Errorf("fixtures: invalid status %q at line %d, column %d (expected: %s, %s, %s)",
					s[2], l, c, StatusAffected, StatusNotAffected, StatusAbsent)
				yield(m, err)
				return
			}

			if !yield(m, nil) {
				return
			}
		}
	}

	return seq, nil
}

// TrackingID is the regexp that a CSAF document's ID must conform to.
// See also: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321124-document-property---tracking---id
var trackingID = regexp.MustCompile(`^[\S](.*[\S])?$`)

// ManifestRecord is a single row from the vulnerability manifest.
type ManifestRecord struct {
	ID      string
	Product string
	Status  VulnerabilityStatus
}

//go:generate go run golang.org/x/tools/cmd/stringer@latest -linecomment -type=VulnerabilityStatus

// VulnerabilityStatus represents the expected vulnerability status for a product
// in acceptance test fixtures.
type VulnerabilityStatus uint

const (
	// StatusUnknown is the zero value and represents an unknown or unspecified status.
	// This is the implicit default per VEX spec for any product not explicitly enumerated.
	// In tests, records with this status do not cause failures if missing from results.
	StatusUnknown VulnerabilityStatus = iota // UNKNOWN

	// StatusAffected indicates the product is vulnerable.
	// In tests, this asserts the CVE+product MUST appear in results as affected.
	StatusAffected // AFFECTED

	// StatusNotAffected indicates the product is known to not be affected.
	// In tests, this asserts the CVE+product MUST appear in results as not-affected.
	// This maps to the VEX "known_not_affected" status.
	StatusNotAffected // NOT_AFFECTED

	// StatusAbsent indicates the product should not appear in results at all.
	// This is used for products that were fixed or filtered out.
	// In tests, this asserts the CVE+product MUST NOT appear in results.
	StatusAbsent // ABSENT
)
