package cvss

import (
	"encoding"
	"fmt"
	"strings"
)

// V3 is a CVSS version 3 score.
type V3 struct {
	mv  [numV3Metrics]byte
	ver int8
}

var (
	_ encoding.TextAppender    = (*V3)(nil)
	_ encoding.TextMarshaler   = (*V3)(nil)
	_ encoding.TextUnmarshaler = (*V3)(nil)
	_ fmt.Stringer             = (*V3)(nil)
)

// ParseV3 parses the provided string as a v3 vector.
func ParseV3(s string) (v V3, err error) {
	return v, v.UnmarshalText([]byte(s))
}

// MarshalText implements [encoding.TextMarshaler].
func (v *V3) MarshalText() (text []byte, err error) {
	b := make([]byte, 0, marshalSize)
	return v.AppendText(b)
}

// AppendText implements [encoding.TextAppender].
func (v *V3) AppendText(b []byte) ([]byte, error) {
	switch v.ver {
	case 0:
		return appendVector(b, `CVSS:3.0`, v)
	case 1:
		return appendVector(b, `CVSS:3.1`, v)
	default:
		// For anything else, fall back to constructing a string on the fly.
	}
	pre := fmt.Sprintf(`CVSS:3.%d`, v.ver)
	return appendVector(b, pre, v)
}

// String implements [fmt.Stringer].
//
// Calling this method on an invalid instance results in an invalid vector string.
func (v *V3) String() string {
	t, err := v.MarshalText()
	if err != nil {
		return `CVSS:3.1/INVALID`
	}
	return string(t)
}

// AppendValue implements [Vector].
func (v *V3) appendValue(b []byte, m V3Metric) ([]byte, error) {
	c := v.mv[int(m)]
	if c == 0 {
		return b, errValueUnset
	}
	return append(b, c), nil
}

// GetScore implements [Vector].
func (v *V3) getScore(m V3Metric) byte {
	b := v.mv[int(m)]
	switch {
	case m >= V3ModifiedAttackVector && b == 0:
		b = v.mv[int(m-V3ModifiedAttackVector)]
	case b == 0:
		b = 'X'
	}
	return b
}

// Get implements [Vector].
func (v *V3) Get(m V3Metric) Value {
	b := v.mv[int(m)]
	if b == 0 {
		return ValueUnset
	}
	if strings.IndexByte(m.validValues(), b) == -1 {
		return ValueInvalid
	}
	return Value(b)
}

// Temporal reports if the vector has "Temporal" metrics.
func (v *V3) Temporal() bool {
	m := v.mv[V3ExploitMaturity : V3ReportConfidence+1]
	for _, v := range m {
		if v != 0 {
			return true
		}
	}
	return false
}

// Environmental reports if the vector has "Environmental" metrics.
func (v *V3) Environmental() (ok bool) {
	m := v.mv[V3ConfidentialityRequirement:]
	for _, v := range m {
		if v != 0 {
			return true
		}
	}
	return false
}

func (*V3) meta() *vectorMetadata { return &v3VectorMeta }

var v3VectorMeta = vectorMetadata{
	Groups: []int{
		int(V3AttackVector), int(V3Availability) + 1,
		int(V3ExploitMaturity), int(V3ReportConfidence) + 1,
		int(V3ReportConfidence), int(V3ModifiedAvailability) + 1,
	},
}

//go:generate go tool stringer -type=V3Metric,v3Valid -linecomment

// V3Metric is a metric in a v3 vector.
type V3Metric int

// These are the metrics defined in the specification.
const (
	V3AttackVector               V3Metric = iota // AV
	V3AttackComplexity                           // AC
	V3PrivilegesRequired                         // PR
	V3UserInteraction                            // UI
	V3Scope                                      // S
	V3Confidentiality                            // C
	V3Integrity                                  // I
	V3Availability                               // A
	V3ExploitMaturity                            // E
	V3RemediationLevel                           // RL
	V3ReportConfidence                           // RC
	V3ConfidentialityRequirement                 // CR
	V3IntegrityRequirement                       // IR
	V3AvailabilityRequirement                    // AR
	V3ModifiedAttackVector                       // MAV
	V3ModifiedAttackComplexity                   // MAC
	V3ModifiedPrivilegesRequired                 // MPR
	V3ModifiedUserInteraction                    // MUI
	V3ModifiedScope                              // MS
	V3ModifiedConfidentiality                    // MC
	V3ModifiedIntegrity                          // MI
	V3ModifiedAvailability                       // MA

	numV3Metrics int = iota
)

// Valid implements [Metric].
func (m V3Metric) validValues() string { return v3Valid(m).String() }

// Num implements [Metric].
func (V3Metric) num() int { return numV3Metrics }

// AppendText implements [encoding.TextAppender].
func (m V3Metric) AppendText(b []byte) ([]byte, error) {
	idx := int(m) - 0
	if m < 0 || idx >= len(_V3Metric_index)-1 {
		return nil, fmt.Errorf("invalid V3Metric: %d", idx)
	}
	return append(b, _V3Metric_name[_V3Metric_index[idx]:_V3Metric_index[idx+1]]...), nil
}

// V3value is the internal-only type that's used to look up valid values for a
// given [V3Metric].
type v3Valid int

const (
	v3AttackVectorValid               v3Valid = iota // NALP
	v3AttackComplexityValid                          // LH
	v3PrivilegesRequiredValid                        // NLH
	v3UserInteractionValid                           // NR
	v3ScopeValid                                     // UC
	v3ConfidentialityValid                           // HLN
	v3IntegrityValid                                 // HLN
	v3AvailabilityValid                              // HLN
	v3ExploitMaturityValid                           // XHFPU
	v3RemediationLevelValid                          // XUWTO
	v3ReportConfidenceValid                          // XCRU
	v3ConfidentialityRequirementValid                // XHML
	v3IntegrityRequirementValid                      // XHML
	v3AvailabilityRequirementValid                   // XHML
	v3ModifiedAttackVectorValid                      // XNALP
	v3ModifiedAttackComplexityValid                  // XLH
	v3ModifiedPrivilegesRequiredValid                // XNLH
	v3ModifiedUserInteractionValid                   // XNR
	v3ModifiedScopeValid                             // XUC
	v3ModifiedConfidentialityValid                   // XHLN
	v3ModifiedIntegrityValid                         // XHLN
	v3ModifiedAvailabilityValid                      // XHLN
)
