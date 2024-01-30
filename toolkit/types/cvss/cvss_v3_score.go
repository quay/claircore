package cvss

import (
	"math"
	"strings"
)

var v3Weights = [numV3Metrics][]float64{
	{0.85, 0.62, 0.55, 0.2}, // AV
	{0.77, 0.44},            // AC
	{0.85, 0.62, 0.27},      // PR
	{0.85, 0.62},            // UI
	{0, 0},                  // S
	{0.56, 0.22, 0},         // C
	{0.56, 0.22, 0},         // I
	{0.56, 0.22, 0},         // A
	// Temporal:
	{1, 1, 0.97, 0.94, 0.91}, // E
	{1, 1, 0.97, 0.96, 0.95}, // RL
	{1, 1, 0.96, 0.92},       // RC
	// Environmental:
	{1, 1.5, 1, 0.5}, // CR
	{1, 1.5, 1, 0.5}, // IR
	{1, 1.5, 1, 0.5}, // AR
	// The following don't have weights defined for "Not Defined" values.
	{math.NaN(), 0.85, 0.62, 0.55, 0.2}, // MAV
	{math.NaN(), 0.77, 0.44},            // MAC
	{math.NaN(), 0.85, 0.62, 0.27},      // MPR
	{math.NaN(), 0.85, 0.62},            // MUI
	{math.NaN(), 0, 0},                  // MS
	{math.NaN(), 0.56, 0.22, 0},         // MC
	{math.NaN(), 0.56, 0.22, 0},         // MI
	{math.NaN(), 0.56, 0.22, 0},         // MA
}

// Score implements [Vector].
//
// The reported score is always a "Temporal" score, and uses the "Environmental"
// equations when Environmental metrics are present.
func (v *V3) Score() float64 {
	var vals [numV3Metrics]float64
	for i := 0; i < numV3Metrics; i++ {
		m := V3Metric(i)
		b := v.getScore(m)
		vi := strings.IndexByte(m.validValues(), b)
		if vi == -1 {
			panic("programmer error: invalid vector constructed")
		}
		vals[i] = v3Weights[i][vi]

		if (m == V3Scope || m == V3ModifiedScope) && b == 'C' {
			var mm V3Metric
			switch m {
			case V3Scope:
				mm = V3PrivilegesRequired
			case V3ModifiedScope:
				mm = V3ModifiedPrivilegesRequired
			default:
				panic("unreachable")
			}
			switch v.getScore(mm) {
			case 'L':
				vals[int(mm)] = 0.68
			case 'H':
				vals[int(mm)] = 0.50
			}
		}
	}

	var round func(float64) float64
	// If environmental metrics are present, many parts of the calculation below
	// are swapped out or have constants modified. There's no good other way to
	// do this that I could work out.
	env := v.Environmental()
	changeExp := 15.0
	switch v.ver {
	case 0:
		round = v30Roundup
	case 1:
		if env {
			changeExp = 13
		}
		round = v31Roundup
	default:
		panic("programmer error: invalid vector constructed")
	}

	var impactSubScore float64
	if env {
		impactSubScore = math.Min(0.915,
			1-
				((1-vals[V3ConfidentialityRequirement]*vals[V3ModifiedConfidentiality])*
					(1-vals[V3IntegrityRequirement]*vals[V3ModifiedIntegrity])*
					(1-vals[V3AvailabilityRequirement]*vals[V3ModifiedAvailability])))
	} else {
		impactSubScore = 1 - ((1 - vals[V3Confidentiality]) * (1 - vals[V3Integrity]) * (1 - vals[V3Availability]))
	}
	var impact float64
	scopeMod := 1.0
	issScale := 1.0
	scope := v.getScore(V3Scope)
	if env {
		if mod := v.getScore(V3ModifiedScope); mod != 'X' {
			scope = mod
		}
		if v.ver == 1 {
			issScale = 0.9731
		}
	}
	switch scope {
	case 'U':
		impact = 6.42 * impactSubScore
	case 'C':
		scopeMod = 1.08
		impact = 7.52*(impactSubScore-0.029) - (3.25 * math.Pow((impactSubScore*issScale)-0.02, changeExp))
	default:
		panic("unreachable")
	}

	var exploitability float64
	if env {
		exploitability = vals[V3ModifiedAttackVector] * vals[V3ModifiedAttackComplexity] * vals[V3ModifiedPrivilegesRequired] * vals[V3ModifiedUserInteraction]
	} else {
		exploitability = vals[V3AttackVector] * vals[V3AttackComplexity] * vals[V3PrivilegesRequired] * vals[V3UserInteraction]
	}
	exploitability *= 8.22

	if impact <= 0 {
		return 0
	}
	base := round(scopeMod * math.Min(impact+exploitability, 10))
	// This is the "Temporal" score, which should be fine to do unconditionally
	// because the "Not Defined" weight is the multiplicative identity.
	score := round(base * vals[V3ExploitMaturity] * vals[V3RemediationLevel] * vals[V3ReportConfidence])
	return score
}

func v30Roundup(f float64) float64 {
	return math.Ceil(f*10) / 10
}

func v31Roundup(f float64) float64 {
	i := int(f * 100_000)
	if (i % 10_000) == 0 {
		return float64(i) / 100_000
	}
	return float64((i/10_000)+1) / 10
}
