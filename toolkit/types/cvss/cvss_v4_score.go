package cvss

import (
	"fmt"
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
	MSD      [numEquivalenceClass]float64
	Frag     [numEquivalenceClass][]*V4
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
	metricsInEQ: [...][]V4Metric{
		{V4AttackVector, V4PrivilegesRequired, V4UserInteraction},
		{V4AttackComplexity, V4AttackRequirements},
		{},
		{V4SubsequentSystemConfidentiality, V4SubsequentSystemIntegrity, V4SubsequentSystemAvailability},
		{V4ExploitMaturity},
		{V4VulnerableSystemConfidentiality, V4VulnerableSystemIntegrity, V4VulnerableSystemAvailability, V4ConfidentialityRequirement, V4IntegrityRequirement, V4AvailabilityRequirement},
	},
	maxFrag: [...][][]*V4{
		{
			{mustParseV4Frag("AV:N/PR:N/UI:N")},
			{mustParseV4Frag("AV:A/PR:N/UI:N"), mustParseV4Frag("AV:N/PR:L/UI:N"), mustParseV4Frag("AV:N/PR:N/UI:P")},
			{mustParseV4Frag("AV:P/PR:N/UI:N"), mustParseV4Frag("AV:A/PR:L/UI:P")},
		},
		{
			{mustParseV4Frag("AC:L/AT:N")},
			{mustParseV4Frag("AC:H/AT:N"), mustParseV4Frag("AC:L/AT:P")},
		},
		{},
		{
			// See the BUG notes for why this can't use the helper:
			// mustParseV4Frag("SC:H/SI:S/SA:S")
			{func() *V4 {
				var v V4
				v.mv[V4SubsequentSystemConfidentiality] = 'H'
				v.mv[V4SubsequentSystemIntegrity] = 'S'
				v.mv[V4SubsequentSystemAvailability] = 'S'
				return &v
			}()},
			{mustParseV4Frag("SC:H/SI:H/SA:H")},
			{mustParseV4Frag("SC:L/SI:L/SA:L")},
		},
		{
			{mustParseV4Frag("E:A")},
			{mustParseV4Frag("E:P")},
			{mustParseV4Frag("E:U")},
		},
		{
			{mustParseV4Frag("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H")},
			{
				mustParseV4Frag("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H"),
				mustParseV4Frag("VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"),
			},
			{
				mustParseV4Frag("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H"),
				mustParseV4Frag("VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"),
			},
			{
				mustParseV4Frag("VC:L/VI:H/VA:L/CR:H/IR:M/AR:H"),
				mustParseV4Frag("VC:L/VI:H/VA:H/CR:H/IR:M/AR:M"),
				mustParseV4Frag("VC:H/VI:L/VA:H/CR:M/IR:H/AR:M"),
				mustParseV4Frag("VC:H/VI:L/VA:L/CR:M/IR:H/AR:H"),
				mustParseV4Frag("VC:L/VI:L/VA:H/CR:H/IR:H/AR:M"),
			},
			{},
			{mustParseV4Frag("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H")},
		},
	},
	eqDepth: [...][]float64{
		{1, 4, 5},
		{1, 2},
		{math.NaN(), math.NaN(), math.NaN()},
		{6, 5, 4},
		{1, 1, 1},
		{7, 6, 8, 8, math.NaN(), 10},
	},
	macrovectorScore: map[macrovector]float64{
		makeMacrovector("000000"): 10,
		makeMacrovector("000001"): 9.9,
		makeMacrovector("000010"): 9.8,
		makeMacrovector("000011"): 9.5,
		makeMacrovector("000020"): 9.5,
		makeMacrovector("000021"): 9.2,
		makeMacrovector("000100"): 10,
		makeMacrovector("000101"): 9.6,
		makeMacrovector("000110"): 9.3,
		makeMacrovector("000111"): 8.7,
		makeMacrovector("000120"): 9.1,
		makeMacrovector("000121"): 8.1,
		makeMacrovector("000200"): 9.3,
		makeMacrovector("000201"): 9,
		makeMacrovector("000210"): 8.9,
		makeMacrovector("000211"): 8,
		makeMacrovector("000220"): 8.1,
		makeMacrovector("000221"): 6.8,
		makeMacrovector("001000"): 9.8,
		makeMacrovector("001001"): 9.5,
		makeMacrovector("001010"): 9.5,
		makeMacrovector("001011"): 9.2,
		makeMacrovector("001020"): 9,
		makeMacrovector("001021"): 8.4,
		makeMacrovector("001100"): 9.3,
		makeMacrovector("001101"): 9.2,
		makeMacrovector("001110"): 8.9,
		makeMacrovector("001111"): 8.1,
		makeMacrovector("001120"): 8.1,
		makeMacrovector("001121"): 6.5,
		makeMacrovector("001200"): 8.8,
		makeMacrovector("001201"): 8,
		makeMacrovector("001210"): 7.8,
		makeMacrovector("001211"): 7,
		makeMacrovector("001220"): 6.9,
		makeMacrovector("001221"): 4.8,
		makeMacrovector("002001"): 9.2,
		makeMacrovector("002011"): 8.2,
		makeMacrovector("002021"): 7.2,
		makeMacrovector("002101"): 7.9,
		makeMacrovector("002111"): 6.9,
		makeMacrovector("002121"): 5,
		makeMacrovector("002201"): 6.9,
		makeMacrovector("002211"): 5.5,
		makeMacrovector("002221"): 2.7,
		makeMacrovector("010000"): 9.9,
		makeMacrovector("010001"): 9.7,
		makeMacrovector("010010"): 9.5,
		makeMacrovector("010011"): 9.2,
		makeMacrovector("010020"): 9.2,
		makeMacrovector("010021"): 8.5,
		makeMacrovector("010100"): 9.5,
		makeMacrovector("010101"): 9.1,
		makeMacrovector("010110"): 9,
		makeMacrovector("010111"): 8.3,
		makeMacrovector("010120"): 8.4,
		makeMacrovector("010121"): 7.1,
		makeMacrovector("010200"): 9.2,
		makeMacrovector("010201"): 8.1,
		makeMacrovector("010210"): 8.2,
		makeMacrovector("010211"): 7.1,
		makeMacrovector("010220"): 7.2,
		makeMacrovector("010221"): 5.3,
		makeMacrovector("011000"): 9.5,
		makeMacrovector("011001"): 9.3,
		makeMacrovector("011010"): 9.2,
		makeMacrovector("011011"): 8.5,
		makeMacrovector("011020"): 8.5,
		makeMacrovector("011021"): 7.3,
		makeMacrovector("011100"): 9.2,
		makeMacrovector("011101"): 8.2,
		makeMacrovector("011110"): 8,
		makeMacrovector("011111"): 7.2,
		makeMacrovector("011120"): 7,
		makeMacrovector("011121"): 5.9,
		makeMacrovector("011200"): 8.4,
		makeMacrovector("011201"): 7,
		makeMacrovector("011210"): 7.1,
		makeMacrovector("011211"): 5.2,
		makeMacrovector("011220"): 5,
		makeMacrovector("011221"): 3,
		makeMacrovector("012001"): 8.6,
		makeMacrovector("012011"): 7.5,
		makeMacrovector("012021"): 5.2,
		makeMacrovector("012101"): 7.1,
		makeMacrovector("012111"): 5.2,
		makeMacrovector("012121"): 2.9,
		makeMacrovector("012201"): 6.3,
		makeMacrovector("012211"): 2.9,
		makeMacrovector("012221"): 1.7,
		makeMacrovector("100000"): 9.8,
		makeMacrovector("100001"): 9.5,
		makeMacrovector("100010"): 9.4,
		makeMacrovector("100011"): 8.7,
		makeMacrovector("100020"): 9.1,
		makeMacrovector("100021"): 8.1,
		makeMacrovector("100100"): 9.4,
		makeMacrovector("100101"): 8.9,
		makeMacrovector("100110"): 8.6,
		makeMacrovector("100111"): 7.4,
		makeMacrovector("100120"): 7.7,
		makeMacrovector("100121"): 6.4,
		makeMacrovector("100200"): 8.7,
		makeMacrovector("100201"): 7.5,
		makeMacrovector("100210"): 7.4,
		makeMacrovector("100211"): 6.3,
		makeMacrovector("100220"): 6.3,
		makeMacrovector("100221"): 4.9,
		makeMacrovector("101000"): 9.4,
		makeMacrovector("101001"): 8.9,
		makeMacrovector("101010"): 8.8,
		makeMacrovector("101011"): 7.7,
		makeMacrovector("101020"): 7.6,
		makeMacrovector("101021"): 6.7,
		makeMacrovector("101100"): 8.6,
		makeMacrovector("101101"): 7.6,
		makeMacrovector("101110"): 7.4,
		makeMacrovector("101111"): 5.8,
		makeMacrovector("101120"): 5.9,
		makeMacrovector("101121"): 5,
		makeMacrovector("101200"): 7.2,
		makeMacrovector("101201"): 5.7,
		makeMacrovector("101210"): 5.7,
		makeMacrovector("101211"): 5.2,
		makeMacrovector("101220"): 5.2,
		makeMacrovector("101221"): 2.5,
		makeMacrovector("102001"): 8.3,
		makeMacrovector("102011"): 7,
		makeMacrovector("102021"): 5.4,
		makeMacrovector("102101"): 6.5,
		makeMacrovector("102111"): 5.8,
		makeMacrovector("102121"): 2.6,
		makeMacrovector("102201"): 5.3,
		makeMacrovector("102211"): 2.1,
		makeMacrovector("102221"): 1.3,
		makeMacrovector("110000"): 9.5,
		makeMacrovector("110001"): 9,
		makeMacrovector("110010"): 8.8,
		makeMacrovector("110011"): 7.6,
		makeMacrovector("110020"): 7.6,
		makeMacrovector("110021"): 7,
		makeMacrovector("110100"): 9,
		makeMacrovector("110101"): 7.7,
		makeMacrovector("110110"): 7.5,
		makeMacrovector("110111"): 6.2,
		makeMacrovector("110120"): 6.1,
		makeMacrovector("110121"): 5.3,
		makeMacrovector("110200"): 7.7,
		makeMacrovector("110201"): 6.6,
		makeMacrovector("110210"): 6.8,
		makeMacrovector("110211"): 5.9,
		makeMacrovector("110220"): 5.2,
		makeMacrovector("110221"): 3,
		makeMacrovector("111000"): 8.9,
		makeMacrovector("111001"): 7.8,
		makeMacrovector("111010"): 7.6,
		makeMacrovector("111011"): 6.7,
		makeMacrovector("111020"): 6.2,
		makeMacrovector("111021"): 5.8,
		makeMacrovector("111100"): 7.4,
		makeMacrovector("111101"): 5.9,
		makeMacrovector("111110"): 5.7,
		makeMacrovector("111111"): 5.7,
		makeMacrovector("111120"): 4.7,
		makeMacrovector("111121"): 2.3,
		makeMacrovector("111200"): 6.1,
		makeMacrovector("111201"): 5.2,
		makeMacrovector("111210"): 5.7,
		makeMacrovector("111211"): 2.9,
		makeMacrovector("111220"): 2.4,
		makeMacrovector("111221"): 1.6,
		makeMacrovector("112001"): 7.1,
		makeMacrovector("112011"): 5.9,
		makeMacrovector("112021"): 3,
		makeMacrovector("112101"): 5.8,
		makeMacrovector("112111"): 2.6,
		makeMacrovector("112121"): 1.5,
		makeMacrovector("112201"): 2.3,
		makeMacrovector("112211"): 1.3,
		makeMacrovector("112221"): 0.6,
		makeMacrovector("200000"): 9.3,
		makeMacrovector("200001"): 8.7,
		makeMacrovector("200010"): 8.6,
		makeMacrovector("200011"): 7.2,
		makeMacrovector("200020"): 7.5,
		makeMacrovector("200021"): 5.8,
		makeMacrovector("200100"): 8.6,
		makeMacrovector("200101"): 7.4,
		makeMacrovector("200110"): 7.4,
		makeMacrovector("200111"): 6.1,
		makeMacrovector("200120"): 5.6,
		makeMacrovector("200121"): 3.4,
		makeMacrovector("200200"): 7,
		makeMacrovector("200201"): 5.4,
		makeMacrovector("200210"): 5.2,
		makeMacrovector("200211"): 4,
		makeMacrovector("200220"): 4,
		makeMacrovector("200221"): 2.2,
		makeMacrovector("201000"): 8.5,
		makeMacrovector("201001"): 7.5,
		makeMacrovector("201010"): 7.4,
		makeMacrovector("201011"): 5.5,
		makeMacrovector("201020"): 6.2,
		makeMacrovector("201021"): 5.1,
		makeMacrovector("201100"): 7.2,
		makeMacrovector("201101"): 5.7,
		makeMacrovector("201110"): 5.5,
		makeMacrovector("201111"): 4.1,
		makeMacrovector("201120"): 4.6,
		makeMacrovector("201121"): 1.9,
		makeMacrovector("201200"): 5.3,
		makeMacrovector("201201"): 3.6,
		makeMacrovector("201210"): 3.4,
		makeMacrovector("201211"): 1.9,
		makeMacrovector("201220"): 1.9,
		makeMacrovector("201221"): 0.8,
		makeMacrovector("202001"): 6.4,
		makeMacrovector("202011"): 5.1,
		makeMacrovector("202021"): 2,
		makeMacrovector("202101"): 4.7,
		makeMacrovector("202111"): 2.1,
		makeMacrovector("202121"): 1.1,
		makeMacrovector("202201"): 2.4,
		makeMacrovector("202211"): 0.9,
		makeMacrovector("202221"): 0.4,
		makeMacrovector("210000"): 8.8,
		makeMacrovector("210001"): 7.5,
		makeMacrovector("210010"): 7.3,
		makeMacrovector("210011"): 5.3,
		makeMacrovector("210020"): 6,
		makeMacrovector("210021"): 5,
		makeMacrovector("210100"): 7.3,
		makeMacrovector("210101"): 5.5,
		makeMacrovector("210110"): 5.9,
		makeMacrovector("210111"): 4,
		makeMacrovector("210120"): 4.1,
		makeMacrovector("210121"): 2,
		makeMacrovector("210200"): 5.4,
		makeMacrovector("210201"): 4.3,
		makeMacrovector("210210"): 4.5,
		makeMacrovector("210211"): 2.2,
		makeMacrovector("210220"): 2,
		makeMacrovector("210221"): 1.1,
		makeMacrovector("211000"): 7.5,
		makeMacrovector("211001"): 5.5,
		makeMacrovector("211010"): 5.8,
		makeMacrovector("211011"): 4.5,
		makeMacrovector("211020"): 4,
		makeMacrovector("211021"): 2.1,
		makeMacrovector("211100"): 6.1,
		makeMacrovector("211101"): 5.1,
		makeMacrovector("211110"): 4.8,
		makeMacrovector("211111"): 1.8,
		makeMacrovector("211120"): 2,
		makeMacrovector("211121"): 0.9,
		makeMacrovector("211200"): 4.6,
		makeMacrovector("211201"): 1.8,
		makeMacrovector("211210"): 1.7,
		makeMacrovector("211211"): 0.7,
		makeMacrovector("211220"): 0.8,
		makeMacrovector("211221"): 0.2,
		makeMacrovector("212001"): 5.3,
		makeMacrovector("212011"): 2.4,
		makeMacrovector("212021"): 1.4,
		makeMacrovector("212101"): 2.4,
		makeMacrovector("212111"): 1.2,
		makeMacrovector("212121"): 0.5,
		makeMacrovector("212201"): 1,
		makeMacrovector("212211"): 0.3,
		makeMacrovector("212221"): 0.1,
	},
}

// MakeMacrovector is a helper for constructing [scoreData].
func makeMacrovector(s string) (v macrovector) {
	for i, x := range s {
		b, err := strconv.ParseUint(string(x), 10, 8)
		if err != nil {
			panic("programmer error: invalid macrovector string: " + s)
		}
		v[i] = uint8(b)
	}
	return v
}

// MustParseV4Frag is a helper for constructing [scoreData].
func mustParseV4Frag(s string) *V4 {
	var v V4
	if err := parseStringLax(v.mv[:], v4VerHook, v4Rev, s); err != nil {
		panic(fmt.Sprintf("programmer error: bad fragment %q: %v", s, err))
	}
	return &v
}
