package photon

import "github.com/quay/claircore"

const (
	Low       = "Low"
	Moderate  = "Moderate"
	Important = "Important"
	Critical  = "Critical"
)

func NormalizeSeverity(severity string) claircore.Severity {
	switch severity {
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