// Package cvss implements v2.0, v3.0, v3.1, and v4.0 CVSS vectors and scoring.
//
// The primary purpose of this package is to parse CVSS vectors then use the
// parsed representation to calculate the numerical score and produce the
// canonicalized representation of the vector.
//
// # CVSS v2.0
//
// Metrics and scoring is implemented as laid out in the [v2.0 specification].
//
// # CVSS v3.0
//
// Metrics and scoring is implemented as laid out in the [v3.0 specification].
//
// # CVSS v3.1
//
// Metrics and scoring is implemented as laid out in the [v3.1 specification].
//
// # CVSS v4.0
//
// Metrics and scoring is implemented as laid out in the [v4.0 specification].
// The ordering emitted is as specified in revision 1.1, not 1.0.
//
// The v4 scoring system is very complicated and under-specified. This package's
// implementation is built to mirror the Javascript implementation where ever
// the specification is unclear.
//
// There are outstanding issues in the specification as of 2024-01-02; see the
// "Bugs" section of this documentation for details.
//
// [v2.0 specification]: https://www.first.org/cvss/v2/guide
// [v3.0 specification]: https://www.first.org/cvss/v3-0/
// [v3.1 specification]: https://www.first.org/cvss/v3-1/
// [v4.0 specification]: https://www.first.org/cvss/v4-0/
package cvss

import (
	"encoding"
	"errors"
	"fmt"
	"slices"
	"strings"
)

/*
This package is organized according to the CVSS version;
all the needed functionality specific to a version should be grouped into files with a "cvss_vN" prefix, where "N" is the major version number.

The implementations usually abuse the lookup table created by the [stringer] tool to implement validation.
Accordingly, "go generate" must be run whenever a given version's [Metric] constants are modified.

Parsers are built with [ragel].
See the helper script in toolkit/internal/cmd/mkragel for some documentation on how ragel is used.

[stringer]: https://pkg.go.dev/golang.org/x/tools/cmd/stringer
[ragel]: https://www.colm.net/open-source/ragel/
*/
var internalDoc = struct{}{}

// ErrMalformedVector is reported when a vector is invalid in some way.
var ErrMalformedVector = errors.New("malformed vector")

// ErrValueUnset is used by [Vector] implementations to signal a metric's value
// is unset.
var errValueUnset = errors.New("unset")

// ErrValueDefault is used by [Vector] implementations to signal a metric's value
// is unset, but a default value was used for the requested operation.
var errValueDefault = fmt.Errorf("default: %w", errValueUnset)

// MarshalSize is the initial size of the backing slice for
// [encoding.TextMarshaler] implementations.
//
// This was arrived at by trying sizes until [BenchmarkMarshal] reported a
// single allocation for all but the longest V4 vectors.
const marshalSize = 128

// Value is a "packed" representation of the value of a metric.
//
// When possible, this is the first byte of the abbreviated form in the relevant
// specification. This is not possible with v2 vectors, so users may need to use
// [UnparseV2Value] in that case.
type Value byte

// GoString implements [fmt.GoStringer].
func (v Value) GoString() string {
	b := []byte("Value(")
	switch v {
	case 0:
		b = append(b, "Unset"...)
	case 255:
		b = append(b, "Invalid"...)
	default:
		b = append(b, byte(v))
	}
	b = append(b, ')')
	return string(b)
}

// ValueUnset is reported when the packed representation in a Vector is not set.
//
// Methods returning values may translate this into a specification-defined
// Unset/Not Defined/Undefined Value.
const ValueUnset = Value(0)

// ValueInvalid is reported when the packed representation in a Vector is
// invalid.
const ValueInvalid = Value(255)

// Version guesses at the version of a vector string.
func Version(vec string) (v int) {
	v = 2
	switch {
	case strings.HasPrefix(vec, `CVSS:4.0`):
		v = 4
	case strings.HasPrefix(vec, `CVSS:3.0`), strings.HasPrefix(vec, `CVSS:3.1`):
		v = 3
	}
	return v
}

// AppendVector is a generic function to marshal vectors via appending to the
// provided byte slice.
func appendVector[M Metric, V Vector[M]](b []byte, prefix string, v V) ([]byte, error) {
	start := len(b)
	b = append(b, prefix...)
	var err error
	meta := v.meta()
	g := meta.Groups
	for s, e := 0, 1; e < len(g); s, e = s+2, e+2 {
		var set bool
		i, lim := g[s], g[e]
		skipGroup := len(b)
		for ; i < lim; i++ {
			skipMetric := len(b)
			m := M(i)

			b = append(b, '/')
			b, err = m.AppendText(b)
			if err != nil {
				return nil, fmt.Errorf("invalid cvss vector: %w", err)
			}
			b = append(b, ':')

			b, err = v.appendValue(b, m)
			switch {
			case errors.Is(err, nil):
				set = true
			case errors.Is(err, errValueDefault):
			case errors.Is(err, errValueUnset):
				b = b[:skipMetric]
			default:
				return nil, fmt.Errorf("invalid cvss vector: %w", err)
			}
		}
		if !set {
			b = b[:skipGroup]
		}
	}
	// v2 hack: remove the leading slash.
	switch {
	case prefix == "" && start == 0:
		b = b[1:]
	case prefix == "" && start != 0:
		// Handle the case where this function was passed a slice with a
		// non-zero length.
		b = slices.Delete(b, start, start+1)
	}
	return b, nil
}

// Metric is a CVSS metric.
//
// The set of types this describes is namespaced per-version.
type Metric interface {
	~int
	encoding.TextAppender
	fmt.Stringer

	// Valid returns the concatenation of valid values for the metric.
	validValues() string
	// Num returns the number of valid metrics of this type.
	num() int
}

// Vector is a CVSS vector of any version.
type Vector[M Metric] interface {
	encoding.TextAppender
	encoding.TextUnmarshaler
	encoding.TextMarshaler
	fmt.Stringer

	// Get reports the Value for the supplied Metric.
	//
	// V2 vectors require calling [UnparseV2Value] to convert the value to the
	// spec-defined abbreviation.
	Get(M) Value
	// Score reports the score for the Vector. The exact formula used depends on
	// what metrics are present.
	Score() float64
	// Environmental reports if the vector contains environmental metrics.
	Environmental() bool

	// AppendValue is a hook for appending the stringified version of the metric
	// value. If the value is unset, implementations should return the input
	// slice and err == [errValueUnset] rather than a specified default, as
	// defaults are omitted from the string representation.
	appendValue([]byte, M) ([]byte, error)
	// GetScore returns the "packed" value representation after any default
	// rules are applied.
	getScore(M) byte
	// Meta returns the static metadata for this vector.
	meta() *vectorMetadata
}

var (
	_ Vector[V4Metric] = (*V4)(nil)
	_ Vector[V3Metric] = (*V3)(nil)
	_ Vector[V2Metric] = (*V2)(nil)
)

// VectorMetadata is static metadata about a vector.
type vectorMetadata struct {
	// Groups is a slice of boundaries for the groups of the vector.
	//
	// The pairs of ints are [lower, upper).
	Groups []int
}

// Qualitative is the "Qualitative Severity" of a Vector.
type Qualitative int

// The specified qualitative severities.
const (
	_ Qualitative = iota
	None
	Low
	Medium
	High
	Critical
)

//go:generate go tool stringer -type=Qualitative

// QualitativeScore returns the qualitative severity of the provided Vector "v".
//
// There is no defined mapping for v2. The mapping defined for the other
// versions is used.
func QualitativeScore[M Metric, V Vector[M]](v V) (q Qualitative) {
	s := v.Score()
	// The mapping is the same for v3.x and v4.0.
	switch {
	case s == 0:
		q = None
	case s < 4:
		q = Low
	case s < 7:
		q = Medium
	case s < 9:
		q = High
	default:
		q = Critical
	}
	return q
}
