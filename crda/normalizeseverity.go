package crda

import "github.com/quay/claircore"

const (
	Low      = "low"
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

// NormalizeSeverity takes a string[1] and normalizes it to
// a claircore.Severity.
// [1] https://github.com/fabric8-analytics/fabric8-analytics-server/blob/master/api_specs/v2/stack_analyses.yaml#L178
func normalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case Low:
		return claircore.Low
	case Medium:
		return claircore.Medium
	case High:
		return claircore.High
	case Critical:
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
