package osv

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

// FromCVSS3 is an attempt at an implementation of the scale and formulas
// described here: https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale
func fromCVSS3(ctx context.Context, s string) (sev claircore.Severity, err error) {
	ms := strings.Split(strings.TrimRight(s, "/"), "/") // "m" as in "metric"
	if !strings.HasPrefix(ms[0], "CVSS:3") {
		return 0, fmt.Errorf("unknown label: %q", ms[0])
	}
	ver, err := strconv.ParseInt(ms[0][7:], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unknown label: %q", ms[0])
	}
	switch ver {
	case 0, 1:
		// As far as I can tell, the equations for calculating v3.0 and v3.1
		// "base" scores are the same.
	default:
		zlog.Warn(ctx).
			Str("version", ms[0]).
			Msg("unknown version, interpreting as CVSSv3.1")
	}
	if len(ms) < 9 {
		return 0, fmt.Errorf("bad vector: %q", s)
	}
	// Giant switch ahoy
	var ns [8]float64
	for _, m := range ms[1:] {
		n, v, ok := strings.Cut(m, ":")
		if !ok {
			return 0, fmt.Errorf("bad metric: %q", m)
		}
		switch n {
		// Base metrics:
		case `AV`:
			const i = 0
			switch v {
			case `N`:
				ns[i] = 0.85
			case `A`:
				ns[i] = 0.62
			case `L`:
				ns[i] = 0.55
			case `P`:
				ns[i] = 0.2
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `AC`:
			const i = 1
			switch v {
			case `L`:
				ns[i] = 0.77
			case `H`:
				ns[i] = 0.44
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `PR`:
			const i = 2
			switch v {
			case `N`:
				ns[i] = 0.85
			case `L`:
				ns[i] = 0.62 // Fixup later
			case `H`:
				ns[i] = 0.27 // Fixup later
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `UI`:
			const i = 3
			switch v {
			case `N`:
				ns[i] = 0.85
			case `R`:
				ns[i] = 0.62
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `S`:
			const i = 4
			// This is a cheat. Encode "changed" as 1. Not actually used in
			// calculations, just changes the values used for other metrics.
			switch v {
			case `U`:
				ns[i] = 0
			case `C`:
				ns[i] = 1
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `C`:
			const i = 5
			switch v {
			case `H`:
				ns[i] = 0.56
			case `L`:
				ns[i] = 0.22
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `I`:
			const i = 6
			switch v {
			case `H`:
				ns[i] = 0.56
			case `L`:
				ns[i] = 0.22
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `A`:
			const i = 7
			switch v {
			case `H`:
				ns[i] = 0.56
			case `L`:
				ns[i] = 0.22
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `E`, `RL`, `RC`, `CR`, `IR`, `AR`, `MAV`, `MAC`, `MPR`, `MUI`, `MS`, `MC`, `MI`, `MA`:
			// Ignore temporal and environmental metrics.
		default:
			return 0, fmt.Errorf("bad metric: %q", m)
		}
	}
	changed := ns[4] != 0 // if Scope == Changed
	if changed {
		switch ns[ /*Privileges Required*/ 2] {
		case 0.62:
			ns[2] = 0.68
		case 0.27:
			ns[2] = 0.5
		}
	}

	var score float64
	iss := 1 - ((1 - ns[ /*C*/ 5]) * (1 - ns[ /*I*/ 6]) * (1 - ns[ /*A*/ 7]))
	var imp float64
	if changed {
		imp = 7.52*(iss-0.029) - 3.25*math.Pow((iss-0.02), 15)
	} else {
		imp = iss * 6.42
	}
	if imp > 0 { // Score is 0 when impact is 0 or below.
		exp := 8.22 * ns[ /*AV*/ 0] * ns[ /*AC*/ 1] * ns[ /*PR*/ 2] * ns[ /*UI*/ 3]
		s := exp + imp
		if changed {
			s *= 1.08
		}
		s = math.Min(s, 10)
		// Roundup function, as spec'd.
		i := int(s * 100_000)
		if (i % 10_000) == 0 {
			score = float64(i) / 100_000.0
		} else {
			score = ((float64(i) / 10_000) + 1) / 10.0
		}
	}

	// See https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	case score == 0:
		sev = claircore.Negligible // aka None
	case score < 4:
		sev = claircore.Low
	case score < 7:
		sev = claircore.Medium
	case score < 9:
		sev = claircore.High
	case score <= 10:
		sev = claircore.Critical
	default:
		return sev, fmt.Errorf("bogus score: %02f", score)
	}
	return sev, nil
}

// FromCVSS2 is an attempt at an implementation of the formulas
// described here: https://www.first.org/cvss/v2/guide
func fromCVSS2(s string) (sev claircore.Severity, err error) {
	ms := strings.Split(s, "/") // "m" as in "metric"
	if len(ms) < 6 {
		return 0, fmt.Errorf("bad vector: %q", s)
	}
	// Giant switch ahoy
	var ns [6]float64
	for _, m := range ms {
		n, v, ok := strings.Cut(m, ":")
		if !ok {
			return 0, fmt.Errorf("bad metric: %q", m)
		}
		switch n {
		// Base metrics:
		case `AV`:
			const i = 0
			switch v {
			case `N`:
				ns[i] = 1
			case `A`:
				ns[i] = 0.646
			case `L`:
				ns[i] = 0.395
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `AC`:
			const i = 1
			switch v {
			case `L`:
				ns[i] = 0.71
			case `M`:
				ns[i] = 0.61
			case `H`:
				ns[i] = 0.35
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `Au`:
			const i = 2
			switch v {
			case `M`:
				ns[i] = 0.45
			case `S`:
				ns[i] = 0.56
			case `N`:
				ns[i] = 0.704
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `C`:
			const i = 3
			switch v {
			case `C`:
				ns[i] = 0.660
			case `P`:
				ns[i] = 0.275
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `I`:
			const i = 4
			switch v {
			case `C`:
				ns[i] = 0.660
			case `P`:
				ns[i] = 0.275
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `A`:
			const i = 5
			switch v {
			case `C`:
				ns[i] = 0.660
			case `P`:
				ns[i] = 0.275
			case `N`:
				ns[i] = 0
			default:
				return 0, fmt.Errorf("bad metric value: %q", m)
			}
		case `E`, `RL`, `RC`, `CDP`, `TD`, `CR`, `IR`, `AR`:
			// Ignore temporal and environmental metrics.
		default:
			return 0, fmt.Errorf("bad metric: %q", m)
		}
	}

	var score float64
	exploitability := 20 * ns[ /*AV*/ 0] * ns[ /*AC*/ 1] * ns[ /*Au*/ 2]
	impact := 10.41 * (1 - (1-ns[ /*C*/ 3])*(1-ns[ /*I*/ 4])*(1-ns[ /*A*/ 5]))
	var fImpact float64
	if impact != 0 {
		fImpact = 1.176
	}
	score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact
	// An attempt to "round_to_1_decimal," per spec.
	score = math.Round(score*10) / 10.0
	score = math.Min(score, 10)

	// See https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	case score < 4:
		sev = claircore.Low
	case score < 7:
		sev = claircore.Medium
	case score <= 10:
		sev = claircore.High
	default:
		return sev, fmt.Errorf("bogus score: %02f", score)
	}
	return sev, nil
}

// returns severity basd on String
func fromString(s string) (sev claircore.Severity, err error) {

	switch {
	case strings.EqualFold(s, "none"):
		sev = claircore.Negligible
	case strings.EqualFold(s, "low"):
		sev = claircore.Low
	case strings.EqualFold(s, "medium"):
		sev = claircore.Medium
	case strings.EqualFold(s, "high"):
		sev = claircore.High
	case strings.EqualFold(s, "critical"):
		sev = claircore.Critical
	default:
		return sev, fmt.Errorf("bogus score: %v", s)
	}
	return sev, nil
}
