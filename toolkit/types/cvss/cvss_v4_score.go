package cvss

import (
	"math"
	"strconv"
	"strings"
)

const (
	eq1 int = iota // EQ1
	eq2            // EQ2
	eq3            // EQ3
	eq4            // EQ4
	eq5            // EQ5
	eq6            // EQ3+6
	numEquivalenceClass

	eq3and6 = eq6
)

// Scorecalc is a helper type for doing the v4 score calculation.
type scorecalc struct {
	Frag     [numEquivalenceClass][]*V4
	MSD      [numEquivalenceClass]float64
	Dist     [numEquivalenceClass]float64
	PropDist [numEquivalenceClass]float64
}

// ForEach is a helper for iterating over all equivalence classes and
// calculating the correct index for lookups.
func (c *scorecalc) ForEach(cur *macrovector, f func(int, int)) {
	for i := 0; i < numEquivalenceClass; i++ {
		if i == eq3 {
			continue
		}
		var idx int
		switch i {
		case eq3and6:
			idx = int(cur[eq6] + (cur[eq3] * 2))
		default:
			idx = int(cur[i])
		}
		f(i, idx)
	}
}

// Init poisons the values for the "EQ3" equivalence class.
//
// EQ3 is combined with EQ6 and handled in that value, so doing this will cause
// any computation using the EQ3 values accidentally to be obviously wrong.
func (c *scorecalc) Init() {
	c.MSD[eq3] = math.NaN()
	c.Dist[eq3] = math.NaN()
	c.PropDist[eq3] = math.NaN()
}

// Mean returns the arithmetic mean of the values present in the PropDist
// member.
//
// If only NaN values are present, 0 is returned.
func (c *scorecalc) Mean() (m float64) {
	var n float64
	for _, f := range c.PropDist[:] {
		if !math.IsNaN(f) {
			n++
			m += f
		}
	}
	if n == 0 {
		return 0
	}
	m /= n
	return m
}

// Score implements [Vector].
//
// Unlike [V2.Score] and [V3.Score], there's not a set of scores for a given
// vector, there's only one.
func (v *V4) Score() float64 {
	var nonzero uint8
	for _, m := range []V4Metric{
		V4VulnerableSystemConfidentiality,
		V4SubsequentSystemConfidentiality,
		V4VulnerableSystemIntegrity,
		V4SubsequentSystemIntegrity,
		V4VulnerableSystemAvailability,
		V4SubsequentSystemAvailability,
	} {
		if v.mv[m] != 'N' {
			nonzero++
		}
	}
	if nonzero == 0 {
		return 0
	}
	/*
		1. For each of the EQs
			a. The maximal scoring difference is determined as the difference between the
			   current MacroVector and the lower MacroVector
				i. if there is no lower MacroVector the available distance is set to NaN and
				   then ignored in the further calculations
			b. The severity distance of the to-be scored vector from a highest severity vector in
			   the same MacroVector is determined
			c. The proportion of the distance is determined by dividing the severity distance of
			   the to-be-scored vector by the depth of the MacroVector
			d. The maximal scoring difference is multiplied by the proportion of distance
		2. The mean of the above computed proportional distances is computed
		3. The score of the vector is the score of the MacroVector (i.e. the score of the highest
		   severity vector) minus the mean distance so computed. This score is rounded to one
		   decimal place.
	*/
	// The scoring algorithm is entirely too complex.
	//
	// This implementation ends up having slightly different values during the
	// calculation from the Javascript reference implementation due to that
	// implementation's distance calculations using 0.1 as the unit instead of
	// 1. This shouldn't affect the output because the spec lays out how and
	// when to round the output.

	var calc scorecalc
	calc.Init()
	cur := v.macrovector()
	value := scoreData.macrovectorScore[cur]
	calc.ForEach(&cur, func(i, _ int) {
		var ok bool
		var s float64
		low := cur
		if i == eq3and6 {
			// This logic is ported from the javascript calculator.
			//
			// It would probably be fine to handle the "3" and "6" equivalence
			// classes separately, but the combined subvectors should reduce the
			// number of distance checks needed in the next step.
			switch {
			case cur[eq3] == 1 && cur[eq6] == 1, cur[eq3] == 0 && cur[eq6] == 1:
				low[eq3]++
			case cur[eq3] == 1 && cur[eq6] == 0:
				low[eq6]++
			case cur[eq3] == 0 && cur[eq6] == 0:
				tmp := cur
				low[eq3]++
				tmp[eq6]++
				a, aok := scoreData.macrovectorScore[low]
				if !aok {
					a = math.NaN()
				}
				b, bok := scoreData.macrovectorScore[tmp]
				if !bok {
					b = math.NaN()
				}
				s = math.Max(a, b)
				goto Done
			default:
				low[eq3]++
				low[eq6]++
			}
			s, ok = scoreData.macrovectorScore[low]
			if !ok {
				s = math.NaN()
			}
		} else {
			low[i]++
			s, ok = scoreData.macrovectorScore[low]
			if !ok {
				s = math.NaN()
			}
		}
	Done:
		calc.MSD[i] = value - s
	})

	calc.ForEach(&cur, func(i, idx int) {
		calc.Frag[i] = scoreData.maxFrag[i][idx]
	})

	// This works because the fragments are sorted specially.
	//
	// This would work beautifully as an iterator function.
Done:
	for _, f1 := range calc.Frag[eq1] {
		var upper V4
		upper.compose(f1)
		for _, f2 := range calc.Frag[eq2] {
			upper.compose(f2)
			for _, f4 := range calc.Frag[eq4] {
				upper.compose(f4)
				for _, f5 := range calc.Frag[eq5] {
					upper.compose(f5)
				Search:
					for _, f36 := range calc.Frag[eq3and6] {
						upper.compose(f36)
						d := vecdiff(v, &upper)
						for _, v := range d {
							if v < 0 {
								continue Search
							}
						}
						calc.ForEach(&cur, func(i, _ int) {
							var v float64
							switch i {
							case eq1:
								v = float64(d[V4AttackVector] + d[V4PrivilegesRequired] + d[V4UserInteraction])
							case eq2:
								v = float64(d[V4AttackComplexity] + d[V4AttackRequirements])
							case eq4:
								v = float64(d[V4SubsequentSystemConfidentiality] + d[V4SubsequentSystemIntegrity] + d[V4SubsequentSystemAvailability])
							case eq5:
							case eq3and6:
								v = float64(d[V4VulnerableSystemConfidentiality] + d[V4VulnerableSystemIntegrity] + d[V4VulnerableSystemAvailability])
								v += float64(d[V4ConfidentialityRequirement] + d[V4IntegrityRequirement] + d[V4AvailabilityRequirement])
							}
							calc.Dist[i] = v
						})
						break Done
					}
				}
			}
		}
	}

	calc.ForEach(&cur, func(i, idx int) {
		calc.PropDist[i] = (calc.MSD[i] * (calc.Dist[i] / (scoreData.eqDepth[i][idx])))
	})

	score := value - calc.Mean()
	score = math.Max(score, 0)
	score = math.Min(score, 10)
	return math.Round(score*10) / 10
}

// Compose copies defined values in "f" into "v" and returns "v".
//
// This is like vector addition, but isn't. Addition is not defined for metric
// values. For example, "AV:P + AV:N = AV:N" may make sense,  but it's less
// clear that "AV:L + AV:A = AV:N" is sensible.
func (v *V4) compose(f *V4) *V4 {
	for i, b := range f.mv {
		if b == 0 {
			continue
		}
		v.mv[i] = b
	}
	return v
}

// Vecdiff returns the stepwise difference for every value in the vectors "a"
// and "b".
//
// The returned values are unit-less "steps". This is possible because there's a
// well-defined order of metric values.
func vecdiff(a, b *V4) (d [numV4Metrics]int) {
	// Only bother calculating the metrics that are in the equivalence classes.
	for _, m := range scoreMetrics {
		s := m.validValues()
		// BUG(hank) The spec prescribes the invalid value "Safety (S)" for the
		// "Integrity Impact to the Subsequent System (SI)" and "Availability
		// Impact to the Subsequent System (SA)" metrics for use in the scoring
		// algorithm. These values are only defined for "Modiﬁed Subsequent
		// System Integrity (MSI)" and "Modiﬁed Subsequent System Availability
		// (MSA)" and so are not accepted for inputs.
		if m == V4SubsequentSystemIntegrity || m == V4SubsequentSystemAvailability {
			s = "S" + s
		}
		av, bv := strings.IndexByte(s, a.getScore(m)), strings.IndexByte(s, b.getScore(m))
		d[int(m)] = av - bv
	}
	return d
}

var scoreMetrics = []V4Metric{
	V4AttackVector,
	V4PrivilegesRequired,
	V4UserInteraction,
	V4AttackComplexity,
	V4AttackRequirements,
	V4VulnerableSystemConfidentiality,
	V4VulnerableSystemIntegrity,
	V4VulnerableSystemAvailability,
	V4SubsequentSystemConfidentiality,
	V4SubsequentSystemIntegrity,
	V4SubsequentSystemAvailability,
	V4ConfidentialityRequirement,
	V4IntegrityRequirement,
	V4AvailabilityRequirement,
}

// Macrovector describes a "MacroVector" as defined in Section 8.2.
//
// Macrovectors are a descriptor for a set of vectors that have been judged to
// be similar.
//
// This type follows the convention of the Javascript implementation, where
// every element is the level of the corresponding equivalence class.
type macrovector [numEquivalenceClass]uint8

// String implements [fmt.Stringer].
func (m *macrovector) String() string {
	b := make([]byte, 0, numEquivalenceClass)
	for i := 0; i < numEquivalenceClass; i++ {
		b = strconv.AppendUint(b, uint64(m[i]), 10)
	}
	return string(b)
}

// Macrovector returns the macrovector for the vector "v".
func (v *V4) macrovector() (mvec macrovector) {
	// These are ports of the relevant tables and then beat with De Morgan's laws.

	// EQ1
	switch {
	// AV:N and PR:N and UI:N
	case v.getScore(V4AttackVector) == 'N' && v.getScore(V4PrivilegesRequired) == 'N' && v.getScore(V4UserInteraction) == 'N':
		mvec[0] = 0
	// (AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
	case (v.getScore(V4AttackVector) == 'N' || v.getScore(V4PrivilegesRequired) == 'N' || v.getScore(V4UserInteraction) == 'N') &&
		v.getScore(V4AttackVector) != 'P':
		mvec[0] = 1
	// AV:P or not(AV:N or PR:N or UI:N)
	default:
		mvec[0] = 2
	}

	// EQ2
	switch {
	// AC:L and AT:N
	case v.getScore(V4AttackComplexity) == 'L' && v.getScore(V4AttackRequirements) == 'N':
		mvec[1] = 0
	// not (AC:L and AT:N)
	default:
		mvec[1] = 1
	}

	// EQ3
	switch {
	// VC:H and VI:H
	case v.getScore(V4VulnerableSystemConfidentiality) == 'H' && v.getScore(V4VulnerableSystemIntegrity) == 'H':
		mvec[2] = 0
	// not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
	case v.getScore(V4VulnerableSystemConfidentiality) == 'H' || v.getScore(V4VulnerableSystemIntegrity) == 'H' || v.getScore(V4VulnerableSystemAvailability) == 'H':
		mvec[2] = 1
	// not (VC:H or VI:H or VA:H)
	default:
		mvec[2] = 2
	}

	// EQ4
	//
	// From the spec:
	//	If MSI=X or MSA=X they will default to the corresponding value of SI and
	//	SA according to the rules of Modified Base Metrics in section 4.2 (See
	//	Table 15). So if there are no modified base metrics, the highest value
	//	that EQ4 can reach is 1.
	switch {
	// MSI:S or MSA:S
	case v.getScore(V4ModifiedSubsequentSystemIntegrity) == 'S' || v.getScore(V4ModifiedSubsequentSystemAvailability) == 'S':
		mvec[3] = 0
	// not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
	case v.getScore(V4SubsequentSystemConfidentiality) == 'H' || v.getScore(V4SubsequentSystemIntegrity) == 'H' || v.getScore(V4SubsequentSystemAvailability) == 'H':
		mvec[3] = 1
	// not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
	default:
		mvec[3] = 2
	}

	// EQ5
	// If E=X it will default to the worst case (i.e., E=A).
	switch v.getScore(V4ExploitMaturity) {
	case 'A', 'X':
		mvec[4] = 0
	case 'P':
		mvec[4] = 1
	case 'U':
		mvec[4] = 2
	default:
		panic("unreachable: exhaustive switch")
	}

	// EQ6
	// If CR=X, IR=X or AR=X they will default to the worst case (i.e., CR=H, IR=H and AR=H)
	switch {
	// (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
	case v.getScore(V4ConfidentialityRequirement) == 'H' && v.getScore(V4VulnerableSystemConfidentiality) == 'H' ||
		v.getScore(V4IntegrityRequirement) == 'H' && v.getScore(V4VulnerableSystemIntegrity) == 'H' ||
		v.getScore(V4AvailabilityRequirement) == 'H' && v.getScore(V4VulnerableSystemAvailability) == 'H':
		mvec[5] = 0
	// not (CR:H and VC:H) and not (IR:H and VI:H) and not (AR:H and VA:H)
	default:
		mvec[5] = 1
	}

	return mvec
}
