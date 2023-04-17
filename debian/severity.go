package debian

import (
	"strings"

	"github.com/quay/claircore"
)

func normalizeSeverity(severity string) claircore.Severity {
	switch strings.ToLower(severity) {
	case "unimportant":
		return claircore.Low
	case "low":
		return claircore.Medium
	case "medium":
		return claircore.High
	case "high":
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
