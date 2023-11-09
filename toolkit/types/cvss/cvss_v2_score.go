package cvss

import (
	"math"
	"strings"
)

// The NaNs in here are to make the string index offsets line up, because V2 has
// long metric values.
var v2Weights = [numV2Metrics][]float64{
	{0.395, 0.646, 1.0}, // AV
	{0.35, 0.61, 0.71},  // AC
	{0.45, 0.56, 0.704}, // Au
	{0.0, 0.275, 0.660}, // C
	{0.0, 0.275, 0.660}, // I
	{0.0, 0.275, 0.660}, // A
	// Temporal:
	{0.85, 0.9, math.NaN(), math.NaN(), 0.95, 1.00, 1.00},  // E
	{0.87, math.NaN(), 0.90, math.NaN(), 0.95, 1.00, 1.00}, // RL
	{0.90, math.NaN(), 0.95, math.NaN(), 1.00, 1.00},       // RC
	// Environmental:
	{0, 0.1, 0.3, math.NaN(), 0.4, math.NaN(), 0.5, 0}, // CDP
	{0, 0.25, 0.75, 1.00, 1.00},                        // TD
	{0.5, 1.0, 1.51, 1.0},                              // CR
	{0.5, 1.0, 1.51, 1.0},                              // IR
	{0.5, 1.0, 1.51, 1.0},                              // AR
}

// Score implements [Vector].
//
// The reported score is always an "Environmental" score.
func (v *V2) Score() float64 {
	var vals [numV2Metrics]float64
	for i := 0; i < numV2Metrics; i++ {
		m := V2Metric(i)
		b := v.getScore(m)
		vi := strings.Index(v2Valid(i).String(), v2Unparse(m, b))
		if vi == -1 {
			panic("programmer error: invalid vector constructed")
		}
		vals[i] = v2Weights[i][vi]
	}

	exploitability := 20 * vals[V2AccessVector] * vals[V2AccessComplexity] * vals[V2Authentication]
	// Note: Actually the "AdjustedImpact" calculation.
	impact := math.Min(
		10,
		10.41*(1-
			(1-vals[V2Confidentiality]*vals[V2ConfidentialityRequirement])*
				(1-vals[V2Integrity]*vals[V2IntegrityRequirement])*
				(1-vals[V2Availability]*vals[V2AvailabilityRequirement])),
	)
	fImpact := 1.176
	if impact == 0 {
		fImpact = 0
	}
	base := v2Round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact)
	temporal := v2Round(base * vals[V2Exploitability] * vals[V2RemediationLevel] * vals[V2ReportConfidence])
	environmental := v2Round((temporal + (10-temporal)*vals[V2CollateralDamagePotential]) * vals[V2TargetDistribution])
	score := environmental

	return score
}

func v2Round(f float64) float64 {
	return math.Round(f*10) / 10
}
