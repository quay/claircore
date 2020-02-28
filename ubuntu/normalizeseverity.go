package ubuntu

import "github.com/quay/claircore"

const (
	Untriaged  = "Unknown"
	Negligible = "Negligible"
	Low        = "Low"
	Medium     = "Medium"
	High       = "High"
	Critical   = "Critical"
)

func NormalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case Untriaged:
		return claircore.Unknown
	case Negligible:
		return claircore.Negligible
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
