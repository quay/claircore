package oracle

import "github.com/quay/claircore"

const (
	NA        = "N/A"
	Low       = "LOW"
	Moderate  = "MODERATE"
	Important = "IMPORTANT"
	Critical  = "CRITICAL"
)

func NormalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case NA:
		return claircore.Unknown
	case Low:
		return claircore.Low
	case Moderate:
		return claircore.Medium
	case Important:
		return claircore.High
	case Critical:
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
