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

// ErrValueUnset is used by [Vector.getString] implementations to signal a
// metric's value is unset.
var errValueUnset = errors.New("unset")

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

// MarshalVector is a generic function to marshal vectors.
//
// The [Vector.getString] method is used here.
func marshalVector[M Metric, V Vector[M]](prefix string, v V) ([]byte, error) {
	text := append(make([]byte, 0, 64), prefix...) // Guess at an initial capacity.
	var err error
	// This is a rangefunc-style iterator.
	v.groups(func(b [2]int) bool {
		var set bool
		orig := len(text)
		for i := b[0]; i < b[1]; i++ {
			m := M(i)
			val, err := v.getString(m)
			switch {
			case errors.Is(err, nil):
				set = true
			case errors.Is(err, errValueUnset) && val == "":
				continue
			case errors.Is(err, errValueUnset):
			default:
				err = errors.New("invalid cvss vector")
				return false
			}

			text = append(text, '/')
			text = append(text, m.String()...)
			text = append(text, ':')
			text = append(text, val...)
		}
		if !set {
			text = text[:orig]
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	// v2 hack
	if prefix == "" {
		text = text[1:]
	}
	return text, nil
}

// Metric is a CVSS metric.
//
// The set of types this describes is namespaced per-version.
type Metric interface {
	~int
	fmt.Stringer

	// Valid returns the concatenation of valid values for the metric.
	validValues() string
	// Num returns the number of valid metrics of this type.
	num() int
}

// Vector is a CVSS vector of any version.
type Vector[M Metric] interface {
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

	// GetString is a hook for returning the stringified version of the metric
	// value. If the value is unset, implementations should return err
	// [errValueUnset] rather than a specified default, as defaults are omitted
	// from the string representation.
	//
	// CVSSv2 notably does not use names that are identifiable by a single byte,
	// so they need to be packed and unpacked.
	getString(M) (string, error)
	// GetScore returns the "packed" value representation after any default
	// rules are applied.
	getScore(M) byte
	// Groups is a rangefunc-style iterator returning the bounds for groups of metrics.
	// For a returned value "b", it represents the interval "[b[0], b[1])".
	groups(func([2]int) bool)
}

var (
	_ Vector[V4Metric] = (*V4)(nil)
	_ Vector[V3Metric] = (*V3)(nil)
	_ Vector[V2Metric] = (*V2)(nil)
)

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

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=Qualitative

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
