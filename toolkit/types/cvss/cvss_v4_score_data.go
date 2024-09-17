// Code generated by internal/cmd/v4data. DO NOT EDIT

package cvss

import (
	"math"
)

var _ = math.NaN()

// ScoreData is precomputed data for doing v4 score calculations
var scoreData = struct {
	// MacrovectorScore is the macrovector → score mapping that's incorporated
	// by reference into the spec.
	//
	// See Section 8.3 for the current fixture.
	macrovectorScore map[macrovector]float64
	// MetricsInEQ returns a slice of the metrics in a given equivalence class.
	//
	// See Section 8.2 for how equivalence classes are defined.
	metricsInEQ [numEquivalenceClass][]V4Metric
	// MaxFrag is a lookup table (EQ → level → []*V4) for the "subvectors"
	// representing the sets of metric values that will yield the highest score
	// within the equivalence class' level.
	//
	// This must be in the same order as the reference implementation, not
	// what's in the spec.
	//
	// See Section 8.2 for how equivalence classes and their levels are defined.
	maxFrag [numEquivalenceClass][][]*V4 // Not valid vectors!
	// EqDepth is the depth of the highest macrovector(s) given the equivalence
	// class and level, plus one.
	//
	// This is copied out of the javascript implementation, I have no idea why
	// it's incremented.
	//
	// See Section 8.2 for how "macrovector depth" defined.
	eqDepth [numEquivalenceClass][]float64
}{
	macrovectorScore: map[macrovector]float64{macrovector{0, 0, 0, 0, 0, 0}: 10, macrovector{0, 0, 0, 0, 0, 1}: 9.9, macrovector{0, 0, 0, 0, 1, 0}: 9.8, macrovector{0, 0, 0, 0, 1, 1}: 9.5, macrovector{0, 0, 0, 0, 2, 0}: 9.5, macrovector{0, 0, 0, 0, 2, 1}: 9.2, macrovector{0, 0, 0, 1, 0, 0}: 10, macrovector{0, 0, 0, 1, 0, 1}: 9.6, macrovector{0, 0, 0, 1, 1, 0}: 9.3, macrovector{0, 0, 0, 1, 1, 1}: 8.7, macrovector{0, 0, 0, 1, 2, 0}: 9.1, macrovector{0, 0, 0, 1, 2, 1}: 8.1, macrovector{0, 0, 0, 2, 0, 0}: 9.3, macrovector{0, 0, 0, 2, 0, 1}: 9, macrovector{0, 0, 0, 2, 1, 0}: 8.9, macrovector{0, 0, 0, 2, 1, 1}: 8, macrovector{0, 0, 0, 2, 2, 0}: 8.1, macrovector{0, 0, 0, 2, 2, 1}: 6.8, macrovector{0, 0, 1, 0, 0, 0}: 9.8, macrovector{0, 0, 1, 0, 0, 1}: 9.5, macrovector{0, 0, 1, 0, 1, 0}: 9.5, macrovector{0, 0, 1, 0, 1, 1}: 9.2, macrovector{0, 0, 1, 0, 2, 0}: 9, macrovector{0, 0, 1, 0, 2, 1}: 8.4, macrovector{0, 0, 1, 1, 0, 0}: 9.3, macrovector{0, 0, 1, 1, 0, 1}: 9.2, macrovector{0, 0, 1, 1, 1, 0}: 8.9, macrovector{0, 0, 1, 1, 1, 1}: 8.1, macrovector{0, 0, 1, 1, 2, 0}: 8.1, macrovector{0, 0, 1, 1, 2, 1}: 6.5, macrovector{0, 0, 1, 2, 0, 0}: 8.8, macrovector{0, 0, 1, 2, 0, 1}: 8, macrovector{0, 0, 1, 2, 1, 0}: 7.8, macrovector{0, 0, 1, 2, 1, 1}: 7, macrovector{0, 0, 1, 2, 2, 0}: 6.9, macrovector{0, 0, 1, 2, 2, 1}: 4.8, macrovector{0, 0, 2, 0, 0, 1}: 9.2, macrovector{0, 0, 2, 0, 1, 1}: 8.2, macrovector{0, 0, 2, 0, 2, 1}: 7.2, macrovector{0, 0, 2, 1, 0, 1}: 7.9, macrovector{0, 0, 2, 1, 1, 1}: 6.9, macrovector{0, 0, 2, 1, 2, 1}: 5, macrovector{0, 0, 2, 2, 0, 1}: 6.9, macrovector{0, 0, 2, 2, 1, 1}: 5.5, macrovector{0, 0, 2, 2, 2, 1}: 2.7, macrovector{0, 1, 0, 0, 0, 0}: 9.9, macrovector{0, 1, 0, 0, 0, 1}: 9.7, macrovector{0, 1, 0, 0, 1, 0}: 9.5, macrovector{0, 1, 0, 0, 1, 1}: 9.2, macrovector{0, 1, 0, 0, 2, 0}: 9.2, macrovector{0, 1, 0, 0, 2, 1}: 8.5, macrovector{0, 1, 0, 1, 0, 0}: 9.5, macrovector{0, 1, 0, 1, 0, 1}: 9.1, macrovector{0, 1, 0, 1, 1, 0}: 9, macrovector{0, 1, 0, 1, 1, 1}: 8.3, macrovector{0, 1, 0, 1, 2, 0}: 8.4, macrovector{0, 1, 0, 1, 2, 1}: 7.1, macrovector{0, 1, 0, 2, 0, 0}: 9.2, macrovector{0, 1, 0, 2, 0, 1}: 8.1, macrovector{0, 1, 0, 2, 1, 0}: 8.2, macrovector{0, 1, 0, 2, 1, 1}: 7.1, macrovector{0, 1, 0, 2, 2, 0}: 7.2, macrovector{0, 1, 0, 2, 2, 1}: 5.3, macrovector{0, 1, 1, 0, 0, 0}: 9.5, macrovector{0, 1, 1, 0, 0, 1}: 9.3, macrovector{0, 1, 1, 0, 1, 0}: 9.2, macrovector{0, 1, 1, 0, 1, 1}: 8.5, macrovector{0, 1, 1, 0, 2, 0}: 8.5, macrovector{0, 1, 1, 0, 2, 1}: 7.3, macrovector{0, 1, 1, 1, 0, 0}: 9.2, macrovector{0, 1, 1, 1, 0, 1}: 8.2, macrovector{0, 1, 1, 1, 1, 0}: 8, macrovector{0, 1, 1, 1, 1, 1}: 7.2, macrovector{0, 1, 1, 1, 2, 0}: 7, macrovector{0, 1, 1, 1, 2, 1}: 5.9, macrovector{0, 1, 1, 2, 0, 0}: 8.4, macrovector{0, 1, 1, 2, 0, 1}: 7, macrovector{0, 1, 1, 2, 1, 0}: 7.1, macrovector{0, 1, 1, 2, 1, 1}: 5.2, macrovector{0, 1, 1, 2, 2, 0}: 5, macrovector{0, 1, 1, 2, 2, 1}: 3, macrovector{0, 1, 2, 0, 0, 1}: 8.6, macrovector{0, 1, 2, 0, 1, 1}: 7.5, macrovector{0, 1, 2, 0, 2, 1}: 5.2, macrovector{0, 1, 2, 1, 0, 1}: 7.1, macrovector{0, 1, 2, 1, 1, 1}: 5.2, macrovector{0, 1, 2, 1, 2, 1}: 2.9, macrovector{0, 1, 2, 2, 0, 1}: 6.3, macrovector{0, 1, 2, 2, 1, 1}: 2.9, macrovector{0, 1, 2, 2, 2, 1}: 1.7, macrovector{1, 0, 0, 0, 0, 0}: 9.8, macrovector{1, 0, 0, 0, 0, 1}: 9.5, macrovector{1, 0, 0, 0, 1, 0}: 9.4, macrovector{1, 0, 0, 0, 1, 1}: 8.7, macrovector{1, 0, 0, 0, 2, 0}: 9.1, macrovector{1, 0, 0, 0, 2, 1}: 8.1, macrovector{1, 0, 0, 1, 0, 0}: 9.4, macrovector{1, 0, 0, 1, 0, 1}: 8.9, macrovector{1, 0, 0, 1, 1, 0}: 8.6, macrovector{1, 0, 0, 1, 1, 1}: 7.4, macrovector{1, 0, 0, 1, 2, 0}: 7.7, macrovector{1, 0, 0, 1, 2, 1}: 6.4, macrovector{1, 0, 0, 2, 0, 0}: 8.7, macrovector{1, 0, 0, 2, 0, 1}: 7.5, macrovector{1, 0, 0, 2, 1, 0}: 7.4, macrovector{1, 0, 0, 2, 1, 1}: 6.3, macrovector{1, 0, 0, 2, 2, 0}: 6.3, macrovector{1, 0, 0, 2, 2, 1}: 4.9, macrovector{1, 0, 1, 0, 0, 0}: 9.4, macrovector{1, 0, 1, 0, 0, 1}: 8.9, macrovector{1, 0, 1, 0, 1, 0}: 8.8, macrovector{1, 0, 1, 0, 1, 1}: 7.7, macrovector{1, 0, 1, 0, 2, 0}: 7.6, macrovector{1, 0, 1, 0, 2, 1}: 6.7, macrovector{1, 0, 1, 1, 0, 0}: 8.6, macrovector{1, 0, 1, 1, 0, 1}: 7.6, macrovector{1, 0, 1, 1, 1, 0}: 7.4, macrovector{1, 0, 1, 1, 1, 1}: 5.8, macrovector{1, 0, 1, 1, 2, 0}: 5.9, macrovector{1, 0, 1, 1, 2, 1}: 5, macrovector{1, 0, 1, 2, 0, 0}: 7.2, macrovector{1, 0, 1, 2, 0, 1}: 5.7, macrovector{1, 0, 1, 2, 1, 0}: 5.7, macrovector{1, 0, 1, 2, 1, 1}: 5.2, macrovector{1, 0, 1, 2, 2, 0}: 5.2, macrovector{1, 0, 1, 2, 2, 1}: 2.5, macrovector{1, 0, 2, 0, 0, 1}: 8.3, macrovector{1, 0, 2, 0, 1, 1}: 7, macrovector{1, 0, 2, 0, 2, 1}: 5.4, macrovector{1, 0, 2, 1, 0, 1}: 6.5, macrovector{1, 0, 2, 1, 1, 1}: 5.8, macrovector{1, 0, 2, 1, 2, 1}: 2.6, macrovector{1, 0, 2, 2, 0, 1}: 5.3, macrovector{1, 0, 2, 2, 1, 1}: 2.1, macrovector{1, 0, 2, 2, 2, 1}: 1.3, macrovector{1, 1, 0, 0, 0, 0}: 9.5, macrovector{1, 1, 0, 0, 0, 1}: 9, macrovector{1, 1, 0, 0, 1, 0}: 8.8, macrovector{1, 1, 0, 0, 1, 1}: 7.6, macrovector{1, 1, 0, 0, 2, 0}: 7.6, macrovector{1, 1, 0, 0, 2, 1}: 7, macrovector{1, 1, 0, 1, 0, 0}: 9, macrovector{1, 1, 0, 1, 0, 1}: 7.7, macrovector{1, 1, 0, 1, 1, 0}: 7.5, macrovector{1, 1, 0, 1, 1, 1}: 6.2, macrovector{1, 1, 0, 1, 2, 0}: 6.1, macrovector{1, 1, 0, 1, 2, 1}: 5.3, macrovector{1, 1, 0, 2, 0, 0}: 7.7, macrovector{1, 1, 0, 2, 0, 1}: 6.6, macrovector{1, 1, 0, 2, 1, 0}: 6.8, macrovector{1, 1, 0, 2, 1, 1}: 5.9, macrovector{1, 1, 0, 2, 2, 0}: 5.2, macrovector{1, 1, 0, 2, 2, 1}: 3, macrovector{1, 1, 1, 0, 0, 0}: 8.9, macrovector{1, 1, 1, 0, 0, 1}: 7.8, macrovector{1, 1, 1, 0, 1, 0}: 7.6, macrovector{1, 1, 1, 0, 1, 1}: 6.7, macrovector{1, 1, 1, 0, 2, 0}: 6.2, macrovector{1, 1, 1, 0, 2, 1}: 5.8, macrovector{1, 1, 1, 1, 0, 0}: 7.4, macrovector{1, 1, 1, 1, 0, 1}: 5.9, macrovector{1, 1, 1, 1, 1, 0}: 5.7, macrovector{1, 1, 1, 1, 1, 1}: 5.7, macrovector{1, 1, 1, 1, 2, 0}: 4.7, macrovector{1, 1, 1, 1, 2, 1}: 2.3, macrovector{1, 1, 1, 2, 0, 0}: 6.1, macrovector{1, 1, 1, 2, 0, 1}: 5.2, macrovector{1, 1, 1, 2, 1, 0}: 5.7, macrovector{1, 1, 1, 2, 1, 1}: 2.9, macrovector{1, 1, 1, 2, 2, 0}: 2.4, macrovector{1, 1, 1, 2, 2, 1}: 1.6, macrovector{1, 1, 2, 0, 0, 1}: 7.1, macrovector{1, 1, 2, 0, 1, 1}: 5.9, macrovector{1, 1, 2, 0, 2, 1}: 3, macrovector{1, 1, 2, 1, 0, 1}: 5.8, macrovector{1, 1, 2, 1, 1, 1}: 2.6, macrovector{1, 1, 2, 1, 2, 1}: 1.5, macrovector{1, 1, 2, 2, 0, 1}: 2.3, macrovector{1, 1, 2, 2, 1, 1}: 1.3, macrovector{1, 1, 2, 2, 2, 1}: 0.6, macrovector{2, 0, 0, 0, 0, 0}: 9.3, macrovector{2, 0, 0, 0, 0, 1}: 8.7, macrovector{2, 0, 0, 0, 1, 0}: 8.6, macrovector{2, 0, 0, 0, 1, 1}: 7.2, macrovector{2, 0, 0, 0, 2, 0}: 7.5, macrovector{2, 0, 0, 0, 2, 1}: 5.8, macrovector{2, 0, 0, 1, 0, 0}: 8.6, macrovector{2, 0, 0, 1, 0, 1}: 7.4, macrovector{2, 0, 0, 1, 1, 0}: 7.4, macrovector{2, 0, 0, 1, 1, 1}: 6.1, macrovector{2, 0, 0, 1, 2, 0}: 5.6, macrovector{2, 0, 0, 1, 2, 1}: 3.4, macrovector{2, 0, 0, 2, 0, 0}: 7, macrovector{2, 0, 0, 2, 0, 1}: 5.4, macrovector{2, 0, 0, 2, 1, 0}: 5.2, macrovector{2, 0, 0, 2, 1, 1}: 4, macrovector{2, 0, 0, 2, 2, 0}: 4, macrovector{2, 0, 0, 2, 2, 1}: 2.2, macrovector{2, 0, 1, 0, 0, 0}: 8.5, macrovector{2, 0, 1, 0, 0, 1}: 7.5, macrovector{2, 0, 1, 0, 1, 0}: 7.4, macrovector{2, 0, 1, 0, 1, 1}: 5.5, macrovector{2, 0, 1, 0, 2, 0}: 6.2, macrovector{2, 0, 1, 0, 2, 1}: 5.1, macrovector{2, 0, 1, 1, 0, 0}: 7.2, macrovector{2, 0, 1, 1, 0, 1}: 5.7, macrovector{2, 0, 1, 1, 1, 0}: 5.5, macrovector{2, 0, 1, 1, 1, 1}: 4.1, macrovector{2, 0, 1, 1, 2, 0}: 4.6, macrovector{2, 0, 1, 1, 2, 1}: 1.9, macrovector{2, 0, 1, 2, 0, 0}: 5.3, macrovector{2, 0, 1, 2, 0, 1}: 3.6, macrovector{2, 0, 1, 2, 1, 0}: 3.4, macrovector{2, 0, 1, 2, 1, 1}: 1.9, macrovector{2, 0, 1, 2, 2, 0}: 1.9, macrovector{2, 0, 1, 2, 2, 1}: 0.8, macrovector{2, 0, 2, 0, 0, 1}: 6.4, macrovector{2, 0, 2, 0, 1, 1}: 5.1, macrovector{2, 0, 2, 0, 2, 1}: 2, macrovector{2, 0, 2, 1, 0, 1}: 4.7, macrovector{2, 0, 2, 1, 1, 1}: 2.1, macrovector{2, 0, 2, 1, 2, 1}: 1.1, macrovector{2, 0, 2, 2, 0, 1}: 2.4, macrovector{2, 0, 2, 2, 1, 1}: 0.9, macrovector{2, 0, 2, 2, 2, 1}: 0.4, macrovector{2, 1, 0, 0, 0, 0}: 8.8, macrovector{2, 1, 0, 0, 0, 1}: 7.5, macrovector{2, 1, 0, 0, 1, 0}: 7.3, macrovector{2, 1, 0, 0, 1, 1}: 5.3, macrovector{2, 1, 0, 0, 2, 0}: 6, macrovector{2, 1, 0, 0, 2, 1}: 5, macrovector{2, 1, 0, 1, 0, 0}: 7.3, macrovector{2, 1, 0, 1, 0, 1}: 5.5, macrovector{2, 1, 0, 1, 1, 0}: 5.9, macrovector{2, 1, 0, 1, 1, 1}: 4, macrovector{2, 1, 0, 1, 2, 0}: 4.1, macrovector{2, 1, 0, 1, 2, 1}: 2, macrovector{2, 1, 0, 2, 0, 0}: 5.4, macrovector{2, 1, 0, 2, 0, 1}: 4.3, macrovector{2, 1, 0, 2, 1, 0}: 4.5, macrovector{2, 1, 0, 2, 1, 1}: 2.2, macrovector{2, 1, 0, 2, 2, 0}: 2, macrovector{2, 1, 0, 2, 2, 1}: 1.1, macrovector{2, 1, 1, 0, 0, 0}: 7.5, macrovector{2, 1, 1, 0, 0, 1}: 5.5, macrovector{2, 1, 1, 0, 1, 0}: 5.8, macrovector{2, 1, 1, 0, 1, 1}: 4.5, macrovector{2, 1, 1, 0, 2, 0}: 4, macrovector{2, 1, 1, 0, 2, 1}: 2.1, macrovector{2, 1, 1, 1, 0, 0}: 6.1, macrovector{2, 1, 1, 1, 0, 1}: 5.1, macrovector{2, 1, 1, 1, 1, 0}: 4.8, macrovector{2, 1, 1, 1, 1, 1}: 1.8, macrovector{2, 1, 1, 1, 2, 0}: 2, macrovector{2, 1, 1, 1, 2, 1}: 0.9, macrovector{2, 1, 1, 2, 0, 0}: 4.6, macrovector{2, 1, 1, 2, 0, 1}: 1.8, macrovector{2, 1, 1, 2, 1, 0}: 1.7, macrovector{2, 1, 1, 2, 1, 1}: 0.7, macrovector{2, 1, 1, 2, 2, 0}: 0.8, macrovector{2, 1, 1, 2, 2, 1}: 0.2, macrovector{2, 1, 2, 0, 0, 1}: 5.3, macrovector{2, 1, 2, 0, 1, 1}: 2.4, macrovector{2, 1, 2, 0, 2, 1}: 1.4, macrovector{2, 1, 2, 1, 0, 1}: 2.4, macrovector{2, 1, 2, 1, 1, 1}: 1.2, macrovector{2, 1, 2, 1, 2, 1}: 0.5, macrovector{2, 1, 2, 2, 0, 1}: 1, macrovector{2, 1, 2, 2, 1, 1}: 0.3, macrovector{2, 1, 2, 2, 2, 1}: 0.1},
	metricsInEQ:      [...][]V4Metric{{V4AttackVector, V4PrivilegesRequired, V4UserInteraction}, {V4AttackComplexity, V4AttackRequirements}, {}, {V4SubsequentSystemConfidentiality, V4SubsequentSystemIntegrity, V4SubsequentSystemAvailability}, {V4ExploitMaturity}, {V4VulnerableSystemConfidentiality, V4VulnerableSystemIntegrity, V4VulnerableSystemAvailability, V4ConfidentialityRequirement, V4IntegrityRequirement, V4AvailabilityRequirement}},
	maxFrag:          [...][][]*V4{{{{mv: [...]byte{0x4e, 0x0, 0x0, 0x4e, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x41, 0x0, 0x0, 0x4e, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x4e, 0x0, 0x0, 0x4c, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x4e, 0x0, 0x0, 0x4e, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x50, 0x0, 0x0, 0x4e, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x41, 0x0, 0x0, 0x4c, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}, {{{mv: [...]byte{0x0, 0x4c, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x48, 0x4e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x4c, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}, {}, {{{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x53, 0x53, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x4c, 0x4c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}, {{{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x55, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}, {{{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x4c, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x4d, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x4d, 0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x4c, 0x48, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x48, 0x4c, 0x0, 0x0, 0x0, 0x0, 0x48, 0x4d, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x48, 0x4d, 0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x4c, 0x48, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x48, 0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x4c, 0x4c, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x4c, 0x48, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}, {}, {{mv: [...]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x4c, 0x4c, 0x0, 0x0, 0x0, 0x0, 0x48, 0x48, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}},
	eqDepth:          [...][]float64{{1, 4, 5}, {1, 2}, {math.NaN(), math.NaN(), math.NaN()}, {6, 5, 4}, {1, 1, 1}, {7, 6, 8, 8, math.NaN(), 10}},
}