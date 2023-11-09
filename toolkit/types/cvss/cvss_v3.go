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
	_ encoding.TextMarshaler   = (*V3)(nil)
	_ encoding.TextUnmarshaler = (*V3)(nil)
	_ fmt.Stringer             = (*V3)(nil)
)

// ParseV3 parses the provided string as a v3 vector.
func ParseV3(s string) (v V3, err error) {
	return v, v.UnmarshalText([]byte(s))
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *V3) UnmarshalText(text []byte) error {
	v.ver = -1
	versionHook := func(ver string) error {
		maj, min, ok := strings.Cut(ver, ".")
		if !ok || maj != "3" {
			return fmt.Errorf("%w: bad version: %q", ErrMalformedVector, ver)
		}
		switch min {
		case "0":
			v.ver = 0
		case "1":
			v.ver = 1
		default:
			return fmt.Errorf("%w: bad minor version: %q", ErrMalformedVector, ver)
		}
		return nil
	}
	err := parseStringLax(v.mv[:], versionHook, v3Rev, string(text))
	if err != nil {
		return fmt.Errorf("cvss v3: %w", err)
	}
	for m, b := range v.mv[:V3Availability] {
		if b == 0 {
			return fmt.Errorf("cvss v3: %w: missing metric: %q", ErrMalformedVector, V3Metric(m).String())
		}
	}
	return nil
}

// MarshalText implements [encoding.TextMarshaler].
func (v *V3) MarshalText() (text []byte, err error) {
	return marshalVector[V3Metric](fmt.Sprintf("CVSS:3.%d", v.ver), v)
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

// GetString implements [Vector].
func (v *V3) getString(m V3Metric) (string, error) {
	b := v.mv[int(m)]
	if b == 0 {
		return "", errValueUnset
	}
	return string(b), nil
}

// GetScore implements [Vector].
func (v *V3) getScore(m V3Metric) byte {
	b := v.mv[int(m)]
	if b == 0 {
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
	var ct int
	for _, v := range m {
		if v != 0 {
			ct++
		}
	}
	return ct == len(m)
}

// Environmental reports if the vector has "Environmental" metrics.
func (v *V3) Environmental() (ok bool) {
	m := v.mv[V3ModifiedAttackVector:]
	var ct int
	for _, v := range m {
		if v != 0 {
			ct++
		}
	}
	return ct == len(m)
}

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=V3Metric,v3Valid -linecomment

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

// Parse implements [Metric].
func (m V3Metric) parse(v string) byte { return v[0] }

// Valid implements [Metric].
func (m V3Metric) validValues() string { return v3Valid(m).String() }

// Num implements [Metric].
func (V3Metric) num() int { return numV3Metrics }

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

var v3Rev = mkRevLookup[V3Metric]()
