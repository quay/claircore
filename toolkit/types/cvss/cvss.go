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

The implementations usually abuse the lookup table created by the [stringer] tool to implement parsing and validation.
Accordingly, "go generate" must be run whenever a given version's [Metric] constants are modified.

[stringer]: https://pkg.go.dev/golang.org/x/tools/cmd/stringer
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

// MkRevLookup constructs a reverse-lookup table for the [Metric] M.
//
// This is used to go "backwards" from the [fmt.Stringer] representation.
func mkRevLookup[M Metric]() map[string]M {
	max := M(0).num()
	ret := make(map[string]M, max)
	for i := 0; i < max; i++ {
		m := M(i)
		ret[m.String()] = m
	}
	return ret
}

// MarshalVector is a generic function to marshal vectors.
//
// The [Vector.getString] method is used here.
func marshalVector[M Metric, V Vector[M]](prefix string, v V) ([]byte, error) {
	text := append(make([]byte, 0, 64), prefix...)
	for i := 0; i < M(0).num(); i++ {
		m := M(i)
		val, err := v.getString(m)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, errValueUnset):
			continue
		default:
			return nil, errors.New("invalid cvss vector")
		}
		text = append(text, '/')
		text = append(text, m.String()...)
		text = append(text, ':')
		text = append(text, val...)
	}
	// v2 hack
	if prefix == "" {
		text = text[1:]
	}
	return text, nil
}

// ParseStringLax is a generic function for parsing vectors and fragments of
// vectors.
//
// It is the caller's responsibility to ensure that required metrics are
// populated. The only validation this function provides is at-most-once
// semantics.
func parseStringLax[M Metric](v []byte, ver func(string) error, lookup map[string]M, s string) error {
	elems := strings.Split(s, "/")
	if len(elems) > len(v)+1 { // Extra for the prefix element
		return fmt.Errorf("%w: too many elements", ErrMalformedVector)
	}
	seen := make(map[M]int, len(v))
	for i, e := range elems {
		a, val, ok := strings.Cut(e, ":")
		if !ok {
			return fmt.Errorf("%w: expected %q", ErrMalformedVector, ":")
		}
		if val == "" || a == "" {
			return fmt.Errorf("%w: invalid element: %q", ErrMalformedVector, e)
		}

		// Be maximally flexible here so this is useful throughout the package:
		// A `CVSS` element is only allowed in position 0, but not enforced to
		// be there. This is needed for v2 vectors.
		m, ok := lookup[a]
		if !ok {
			if i == 0 && a == "CVSS" {
				if err := ver(val); err != nil {
					return fmt.Errorf("%w: %w", ErrMalformedVector, err)
				}
				continue
			}
			return fmt.Errorf("%w: unknown abbreviation %q", ErrMalformedVector, a)
		}
		if strings.Index(m.validValues(), val) == -1 {
			return fmt.Errorf("%w: unknown value for %q: %q", ErrMalformedVector, a, val)
		}
		if p, ok := seen[m]; ok {
			return fmt.Errorf("%w: duplicate metric %q: %q and %q", ErrMalformedVector, a, elems[p], val)
		}
		seen[m] = i
		v[m] = m.parse(val)
	}
	return nil
}

// ParseString is a generic function for parsing vectors.
//
// In addition to the guarantees provided by the [parseStringLax] function, this
// function enforces the metrics appear in order (as dictated by the numeric
// value of the [Metric]s), and that the vector is "complete".
func parseString[M Metric](v []byte, ver func(string) error, lookup map[string]M, s string) error {
	elems := strings.Split(s, "/")
	if len(elems) > len(v)+1 { // Extra for the prefix element
		return fmt.Errorf("%w: too many elements", ErrMalformedVector)
	}
	if len(elems) < minVectorLen(len(v)) {
		return fmt.Errorf("%w: too few elements", ErrMalformedVector)
	}
	seen := make([]M, 0, len(v))
	for i, e := range elems {
		a, val, ok := strings.Cut(e, ":")
		if !ok {
			return fmt.Errorf("%w: expected %q", ErrMalformedVector, ":")
		}
		if i == 0 {
			if a != "CVSS" {
				return fmt.Errorf(`%w: expected "CVSS" element`, ErrMalformedVector)
			}
			// Append a bogus Metric to the seen list to keep everything
			// organized.
			seen = append(seen, -1)
			continue
		}
		if val == "" || a == "" {
			return fmt.Errorf("%w: invalid element: %q", ErrMalformedVector, e)
		}

		m, ok := lookup[a]
		if !ok {
			return fmt.Errorf("%w: unknown abbreviation %q", ErrMalformedVector, a)
		}
		if strings.Index(m.validValues(), val) == -1 {
			return fmt.Errorf("%w: unknown value for %q: %q", ErrMalformedVector, a, val)
		}
		seen = append(seen, m)
		switch p := seen[i-1]; {
		case m == p:
			return fmt.Errorf("%w: duplicate metric: %q", ErrMalformedVector, a)
		case m < p:
			return fmt.Errorf("%w: metric out of order: %q", ErrMalformedVector, a)
		default:
		}
		v[m] = m.parse(val)
	}
	return nil
}

// MinVectorLen reports the minimum number of metrics present in a valid vector,
// including the "CVSS" prefix.
func minVectorLen(n int) (l int) {
	switch n {
	case numV4Metrics:
		l = 12
	case numV3Metrics:
		l = 9
	case numV2Metrics:
		panic("programmer error: called with V2 vector")
	default:
		panic(fmt.Sprintf("programmer error: unexpected vector length: %d", n))
	}
	return l
}

// Metric is a CVSS metric.
//
// The set of types this describes is namespaced per-version.
type Metric interface {
	~int
	fmt.Stringer

	// Valid returns the concatenation of valid values for the metric.
	validValues() string
	// Parse returns the "packed" representation for the receiver based on the
	// provided value.
	parse(string) byte
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
