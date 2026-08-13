package cvss

import (
	"encoding"
	"fmt"
	"strings"
)

// V4 is a CVSS version 4 score.
type V4 struct {
	mv [numV4Metrics]byte
}

var (
	_ encoding.TextAppender    = (*V4)(nil)
	_ encoding.TextMarshaler   = (*V4)(nil)
	_ encoding.TextUnmarshaler = (*V4)(nil)
	_ fmt.Stringer             = (*V4)(nil)
)

// ParseV4 parses the provided string as a v4 vector.
func ParseV4(s string) (v V4, err error) {
	return v, v.UnmarshalText([]byte(s))
}

// MarshalText implements [encoding.TextMarshaler].
func (v *V4) MarshalText() (text []byte, err error) {
	b := make([]byte, 0, marshalSize)
	return appendVector(b, `CVSS:4.0`, v)
}

// AppendText implements [encoding.TextAppender].
func (v *V4) AppendText(b []byte) ([]byte, error) {
	return appendVector(b, `CVSS:4.0`, v)
}

// String implements [fmt.Stringer].
//
// Calling this method on an invalid instance results in an invalid vector string.
func (v *V4) String() string {
	t, err := v.MarshalText()
	if err != nil {
		return `CVSS:4.0/INVALID`
	}
	return string(t)
}

// AppendValue implements [Vector].
func (v *V4) appendValue(b []byte, m V4Metric) ([]byte, error) {
	c := v.mv[int(m)]
	if c == 0 {
		return b, errValueUnset
	}
	if m == V4ProviderUrgency {
		switch c {
		case 'C':
			return append(b, "Clear"...), nil
		case 'G':
			return append(b, "Green"...), nil
		case 'A':
			return append(b, "Amber"...), nil
		case 'R':
			return append(b, "Red"...), nil
		}
	}
	return append(b, c), nil
}

// GetScore implements [Vector].
func (v *V4) getScore(m V4Metric) byte {
	b := v.mv[int(m)]
	if m >= V4ExploitMaturity && (b == 0 /* not present */ || b == 'X' /* not defined */) {
		switch m {
		case V4ExploitMaturity:
			b = 'A'
		case V4ConfidentialityRequirement, V4IntegrityRequirement, V4AvailabilityRequirement:
			b = 'H'
		default:
			b = 'X'
		}
		if m >= V4ModifiedAttackVector && m <= V4ModifiedSubsequentSystemAvailability {
			b = v.mv[m-V4ModifiedAttackVector]
		}
	}
	return b
}

// Get implements [Vector].
func (v *V4) Get(m V4Metric) Value {
	b := v.mv[int(m)]
	if b == 0 {
		return ValueUnset
	}
	if strings.IndexByte(m.validValues(), b) == -1 {
		return ValueInvalid
	}
	return Value(b)
}

// Threat reports if the vector has "Threat" metrics.
func (v *V4) Threat() bool {
	return v.mv[V4ExploitMaturity] != 0
}

// Environmental reports if the vector has "Environmental" metrics.
func (v *V4) Environmental() (ok bool) {
	for _, v := range v.mv[V4ConfidentialityRequirement : V4ModifiedSubsequentSystemAvailability+1] {
		if v != 0 {
			ok = true
			break
		}
	}
	return ok
}

// Supplemental reports if the vector has "Supplemental" metrics.
func (v *V4) Supplemental() (ok bool) {
	for _, v := range v.mv[V4Safety:] {
		if v != 0 {
			ok = true
			break
		}
	}
	return ok
}

func (*V4) meta() *vectorMetadata { return &v4VectorMeta }

var v4VectorMeta = vectorMetadata{
	Groups: []int{
		int(V4AttackVector), int(V4SubsequentSystemAvailability) + 1,
		int(V4ExploitMaturity), int(V4ExploitMaturity) + 1,
		int(V4ConfidentialityRequirement), int(V4ModifiedSubsequentSystemAvailability) + 1,
		int(V4Safety), int(V4ProviderUrgency) + 1,
	},
}

//go:generate go tool stringer -type=V4Metric,v4Valid -linecomment

// V4Metric is a metric in a v4 vector.
type V4Metric int

// These are the metrics defined in the specification.
const (
	V4AttackVector                            V4Metric = iota // AV
	V4AttackComplexity                                        // AC
	V4AttackRequirements                                      // AT
	V4PrivilegesRequired                                      // PR
	V4UserInteraction                                         // UI
	V4VulnerableSystemConfidentiality                         // VC
	V4VulnerableSystemIntegrity                               // VI
	V4VulnerableSystemAvailability                            // VA
	V4SubsequentSystemConfidentiality                         // SC
	V4SubsequentSystemIntegrity                               // SI
	V4SubsequentSystemAvailability                            // SA
	V4ExploitMaturity                                         // E
	V4ConfidentialityRequirement                              // CR
	V4IntegrityRequirement                                    // IR
	V4AvailabilityRequirement                                 // AR
	V4ModifiedAttackVector                                    // MAV
	V4ModifiedAttackComplexity                                // MAC
	V4ModifiedAttackRequirements                              // MAT
	V4ModifiedPrivilegesRequired                              // MPR
	V4ModifiedUserInteraction                                 // MUI
	V4ModifiedVulnerableSystemConfidentiality                 // MVC
	V4ModifiedVulnerableSystemIntegrity                       // MVI
	V4ModifiedVulnerableSystemAvailability                    // MVA
	V4ModifiedSubsequentSystemConfidentiality                 // MSC
	V4ModifiedSubsequentSystemIntegrity                       // MSI
	V4ModifiedSubsequentSystemAvailability                    // MSA
	V4Safety                                                  // S
	V4Automatable                                             // AU
	V4Recovery                                                // R
	V4ValueDensity                                            // V
	V4VulnerabilityResponseEffort                             // RE
	V4ProviderUrgency                                         // U

	numV4Metrics int = iota
)

// Valid implements [Metric].
func (m V4Metric) validValues() string { return v4Valid(m).String() }

// Num implements [Metric].
func (V4Metric) num() int { return numV4Metrics }

// AppendText implements [encoding.TextAppender].
func (m V4Metric) AppendText(b []byte) ([]byte, error) {
	idx := int(m) - 0
	if m < 0 || idx >= len(_V4Metric_index)-1 {
		return nil, fmt.Errorf("invalid V4Metric: %d", idx)
	}
	return append(b, _V4Metric_name[_V4Metric_index[idx]:_V4Metric_index[idx+1]]...), nil
}

type v4Valid int

const (
	v4AttackVectorValid                            v4Valid = iota // NALP
	v4AttackComplexityValid                                       // LH
	v4AttackRequirementsValid                                     // NP
	v4PrivilegesRequiredValid                                     // NLH
	v4UserInteractionValid                                        // NPA
	v4VulnerableSystemConfidentialityValid                        // HLN
	v4SubsequentSystemConfidentialityValid                        // HLN
	v4VulnerableSystemIntegrityValid                              // HLN
	v4SubsequentSystemIntegrityValid                              // HLN
	v4VulnerableSystemAvailabilityValid                           // HLN
	v4SubsequentSystemAvailabilityValid                           // HLN
	v4ExploitMaturityValid                                        // XAPU
	v4ConfidentialityRequirementValid                             // XHML
	v4IntegrityRequirementValid                                   // XHML
	v4AvailabilityRequirementValid                                // XHML
	v4ModifiedAttackVectorValid                                   // XNALP
	v4ModifiedAttackComplexityValid                               // XLH
	v4ModifiedAttackRequirementsValid                             // XNP
	v4ModifiedPrivilegesRequiredValid                             // XNLH
	v4ModifiedUserInteractionValid                                // XNPA
	v4ModifiedVulnerableSystemConfidentialityValid                // XHLN
	v4ModifiedVulnerableSystemIntegrityValid                      // XHLN
	v4ModifiedVulnerableSystemAvailabilityValid                   // XHLN
	v4ModifiedSubsequentSystemConfidentialityValid                // XHLN
	v4ModifiedSubsequentSystemIntegrityValid                      // XSHLN
	v4ModifiedSubsequentSystemAvailabilityValid                   // XSHLN
	v4SafetyValid                                                 // XPN
	v4AutomatableValid                                            // XNY
	v4RecoveryValid                                               // XAUI
	v4ValueDensityValid                                           // XDC
	v4VulnerabilityResponseEffortValid                            // XLMH
	v4ProviderUrgencyValid                                        // XRedAmberGreenClear
)
