package osv

import (
	"fmt"
	"strings"

	"github.com/quay/claircore"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

func fromCVSS(vec string) (sev claircore.Severity, err error) {
	// Compute the CVSS score from vector
	var score float64
	switch {
	default:
		v, err := gocvss20.ParseVector(vec)
		if err != nil {
			return claircore.Unknown, err
		}
		score = v.BaseScore()
	case strings.HasPrefix(vec, "CVSS:3.0"):
		v, err := gocvss30.ParseVector(vec)
		if err != nil {
			return claircore.Unknown, err
		}
		score = v.BaseScore()
	case strings.HasPrefix(vec, "CVSS:3.1"):
		v, err := gocvss31.ParseVector(vec)
		if err != nil {
			return claircore.Unknown, err
		}
		score = v.BaseScore()
	case strings.HasPrefix(vec, "CVSS:4.0"):
		v, err := gocvss40.ParseVector(vec)
		if err != nil {
			return claircore.Unknown, err
		}
		score = v.Score()
	}

	// Get corresponding claircore severity.
	switch {
	case score == 0.0:
		sev = claircore.Negligible // aka None
	case score < 4.0:
		sev = claircore.Low
	case score < 7.0:
		sev = claircore.Medium
	case score < 9.0:
		sev = claircore.High
	case score <= 10.0:
		sev = claircore.Critical
	default:
		// This should not happen as it is ensured by the CVSS implementation.
		// Keeping it for safety.
		return sev, fmt.Errorf("bogus score: %02f", score)
	}
	return sev, nil
}
