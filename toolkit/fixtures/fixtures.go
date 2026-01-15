// Package fixtures provides definitions and helpers implementing the [security
// reporting fixture spec].
//
// [security reporting fixture spec]: https://clairproject.org/TODO
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
	MediaTypeVEX       = `application/csaf+json`
	MediaTypeManifest1 = `application/vnd.com.redhat.container.acceptancetest.v1+csv`
	MediaTypeBOM       = `application/spdx+json`
)

// These are the compressed variants of the known media types.
const (
	MediaTypeZstdVEX       = `application/csaf+json+zstd`
	MediaTypeZstdManifest1 = `application/vnd.com.redhat.container.acceptancetest.v1+csv+zstd`
	MediaTypeZstdBOM       = `application/spdx+json+zstd`
)

func ParseManifest(ctx context.Context, mt string, rd io.Reader) (iter.Seq2[ManifestRecord, error], error) {
	mr := csv.NewReader(bufio.NewReader(rd))
	mr.ReuseRecord = true
	mr.Comment = '#'
	switch mt {
	case MediaTypeManifest1, MediaTypeZstdManifest1:
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

			switch {
			case strings.EqualFold(s[2], `affected`):
				m.Status = StatusAffected
			case strings.EqualFold(s[2], `unaffected`):
				m.Status = StatusUnaffected
			default:
				m.Status = StatusUnknown
			}

			if !yield(m, nil) {
				return
			}
		}
	}

	return seq, nil
}

// TrackingID is the regexp that a CSAF document's ID must conform to.
//
// See also: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321124-document-property---tracking---id
var trackingID = regexp.MustCompile(`^[\S](.*[\S])?$`)

type ManifestRecord struct {
	ID      string
	Product string
	Status  VulnerabilityStatus
}

//go:generate go run golang.org/x/tools/cmd/stringer@latest -linecomment -type=VulnerabilityStatus
type VulnerabilityStatus uint

const (
	StatusUnknown    VulnerabilityStatus = iota // UNKNOWN
	StatusAffected                              // AFFECTED
	StatusUnaffected                            // UNAFFECTED
)
