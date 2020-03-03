package aws

import "github.com/quay/claircore"

const (
	Low       = "low"
	Medium    = "medium"
	Important = "important"
	Critical  = "critical"
)

// NormalizeSeverity takes a aws.Severity and normalizes it to
// a claircore.Severity.
func NormalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case Low:
		return claircore.Low
	case Medium:
		return claircore.Medium
	case Important:
		return claircore.High
	case Critical:
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
