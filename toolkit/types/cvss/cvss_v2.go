package cvss

import (
	"encoding"
	"fmt"
	"strings"
)

// V2 is a CVSS version 2 score.
type V2 struct {
	mv [numV2Metrics]byte
}

var (
	_ encoding.TextMarshaler   = (*V2)(nil)
	_ encoding.TextUnmarshaler = (*V2)(nil)
	_ fmt.Stringer             = (*V2)(nil)
)

// ParseV2 parses the provided string as a v2 vector.
func ParseV2(s string) (v V2, err error) {
	return v, v.UnmarshalText([]byte(s))
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *V2) UnmarshalText(text []byte) error {
	disallow := func(_ string) error {
		return fmt.Errorf("unknown metric %q", "CVSS")
	}
	err := parseStringLax(v.mv[:], disallow, v2Rev, string(text))
	if err != nil {
		return fmt.Errorf("cvss v2: %w", err)
	}
	for m, b := range v.mv[:V2Availability+1] { // range inclusive
		if b == 0 {
			return fmt.Errorf("cvss v2: %w: missing metric: %q", ErrMalformedVector, V3Metric(m).String())
		}
	}
	return nil
}

// MarshalText implements [encoding.TextMarshaler].
func (v *V2) MarshalText() (text []byte, err error) {
	// CVSSv2 vectors are not prefixed.
	return marshalVector[V2Metric]("", v)
}

func v2Unparse(m V2Metric, c byte) string {
	switch m {
	case V2Exploitability:
		switch c {
		case 'P':
			return "POC"
		case 'N':
			return "ND"
		}
	case V2RemediationLevel:
		switch c {
		case 'O':
			return "OF"
		case 'T':
			return "TF"
		case 'N':
			return "ND"
		}
	case V2ReportConfidence:
		switch c {
		case 'U':
			return "UC"
		case 'u':
			return "UR"
		case 'N':
			return "ND"
		}
	case V2CollateralDamagePotential:
		switch c {
		case 'M':
			return "MH"
		case 'l':
			return "LM"
		case 'X':
			return "ND"
		}
	case V2TargetDistribution:
		if c == 'X' {
			return "ND"
		}
	case V2ConfidentialityRequirement, V2IntegrityRequirement, V2AvailabilityRequirement:
		if c == 'N' {
			return "ND"
		}
	}
	return string(c)
}

// UnparseV2Value unpacks the Value v into the specification's abbreviation.
//
// Invalid values are returned as-is.
func UnparseV2Value(m V2Metric, v Value) string {
	return v2Unparse(m, byte(v))
}

// String implements [fmt.Stringer].
//
// Calling this method on an invalid instance results in an invalid vector string.
func (v *V2) String() string {
	t, err := v.MarshalText()
	if err != nil {
		return `CVSS:2.0/INVALID`
	}
	return string(t)
}

// GetString implements [Vector].
func (v *V2) getString(m V2Metric) (string, error) {
	b := v.mv[int(m)]
	if b == 0 {
		return "", errValueUnset
	}
	return v2Unparse(m, b), nil
}

// GetScore implements [Vector].
func (v *V2) getScore(m V2Metric) byte {
	b := v.mv[int(m)]
	switch {
	case m <= V2Availability:
	case m <= V2ReportConfidence && b == 0:
		b = 'N'
	case m <= V2AvailabilityRequirement && b == 0:
		switch m {
		case V2CollateralDamagePotential, V2TargetDistribution:
			b = 'X'
		case V2ConfidentialityRequirement, V2IntegrityRequirement, V2AvailabilityRequirement:
			b = 'N'
		}
	}
	return b
}

// Get implements [Vector].
func (v *V2) Get(m V2Metric) Value {
	b := v.mv[int(m)]
	if b == 0 {
		return ValueUnset
	}
	if strings.Index(m.validValues(), v2Unparse(m, b)) == -1 {
		return ValueInvalid
	}
	return Value(b)
}

// Temporal reports if the vector has "Temporal" metrics.
func (v *V2) Temporal() (ok bool) {
	for _, v := range v.mv[V2Exploitability : V2ReportConfidence+1] {
		if v != 0 {
			ok = true
			break
		}
	}
	return ok
}

// Environmental reports if the vector has "Environmental" metrics.
func (v *V2) Environmental() (ok bool) {
	for _, v := range v.mv[V2CollateralDamagePotential:] {
		if v != 0 {
			ok = true
			break
		}
	}
	return ok
}

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=V2Metric,v2Valid -linecomment

// V2Metric is a metric in a v2 vector.
type V2Metric int

// These are the metrics defined in the specification.
const (
	V2AccessVector               V2Metric = iota // AV
	V2AccessComplexity                           // AC
	V2Authentication                             // Au
	V2Confidentiality                            // C
	V2Integrity                                  // I
	V2Availability                               // A
	V2Exploitability                             // E
	V2RemediationLevel                           // RL
	V2ReportConfidence                           // RC
	V2CollateralDamagePotential                  // CDP
	V2TargetDistribution                         // TD
	V2ConfidentialityRequirement                 // CR
	V2IntegrityRequirement                       // IR
	V2AvailabilityRequirement                    // AR

	numV2Metrics int = iota
)

// Parse implements [Metric].
func (m V2Metric) parse(v string) byte {
	switch m {
	case V2ReportConfidence:
		if v == "UR" {
			return 'u'
		}
	case V2CollateralDamagePotential:
		switch v {
		case "LM":
			return 'l'
		case "ND":
			return 'X'
		}
	case V2TargetDistribution:
		if v == "ND" {
			return 'X'
		}
	}
	return v[0]
}

// Valid implements [Metric].
func (m V2Metric) validValues() string { return v2Valid(m).String() }

// Num implements [Metric].
func (V2Metric) num() int { return numV2Metrics }

type v2Valid int

const (
	v2AccessVectorValid               v2Valid = iota // LAN
	v2AccessComplexityValid                          // HML
	v2AuthenticationValid                            // MSN
	v2ConfidentialityValid                           // NPC
	v2IntegrityValid                                 // NPC
	v2AvailabilityValid                              // NPC
	v2ExploitabilityValid                            // UPOCFHND
	v2RemediationLevelValid                          // OFTFWUND
	v2ReportConfidenceValid                          // UCURCND
	v2CollateralDamagePotentialValid                 // NLLMMHHND
	v2TargetDistributionValid                        // NLMHND
	v2ConfidentialityRequirementValid                // LMHND
	v2IntegrityRequirementValid                      // LMHND
	v2AvailabilityRequirementValid                   // LMHND
)

var v2Rev = mkRevLookup[V2Metric]()
