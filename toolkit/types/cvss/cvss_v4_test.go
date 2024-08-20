package cvss

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestV4(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		Error[V4, V4Metric, *V4](t, LoadErrorFixture(t, "testdata/v4_error.list"))
	})

	t.Run("Roundtrip", func(t *testing.T) {
		Roundtrip[V4, V4Metric, *V4](t, LoadRoundtripFixture(t, "testdata/v4_roundtrip.list"))
	})

	t.Run("Simple", func(t *testing.T) {
		vec := V4{}
		vec.mv[V4AttackVector] = 'N'
		vec.mv[V4AttackComplexity] = 'L'
		vec.mv[V4AttackRequirements] = 'N'
		vec.mv[V4PrivilegesRequired] = 'N'
		vec.mv[V4UserInteraction] = 'N'
		vec.mv[V4VulnerableSystemConfidentiality] = 'N'
		vec.mv[V4SubsequentSystemConfidentiality] = 'N'
		vec.mv[V4VulnerableSystemIntegrity] = 'N'
		vec.mv[V4SubsequentSystemIntegrity] = 'N'
		vec.mv[V4VulnerableSystemAvailability] = 'N'
		vec.mv[V4SubsequentSystemAvailability] = 'N'

		t.Logf("vector: %q", &vec)
		t.Logf("AV: %c", vec.Get(V4AttackVector))
		t.Logf("AC: %c", vec.Get(V4AttackComplexity))
		t.Logf("E: %c", vec.Get(V4ExploitMaturity))
	})

	t.Run("Spec", func(t *testing.T) {
		t.Run("Valid", func(t *testing.T) {
			tt := []v4Testcase{
				{
					In: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
				},
				{
					In: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A",
				},
				{
					In: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P",
				},
				{
					In: "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H",
				},
				{
					In: "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red",
				},
				{
					In: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green",
				},
			}
			for _, tc := range tt {
				tc.Check(t)
			}
		})
		t.Run("Invalid", func(t *testing.T) {
		})
	})

	t.Run("Score", func(t *testing.T) {
		Score[V4, V4Metric, *V4](t, LoadScoreFixture(t, "testdata/v4_score.list"))
	})
}

type v4Testcase struct {
	Want *V4
	Err  error
	Name string
	In   string
}

func (tc *v4Testcase) Check(t *testing.T) {
	t.Helper()
	n := tc.In
	if tc.Name != "" {
		n = tc.Name
	}
	t.Run(n, func(t *testing.T) {
		var vec V4
		err := vec.UnmarshalText([]byte(tc.In))
		if tc.Err != nil && err != nil {
			if got, want := err, tc.Err; !errors.Is(err, tc.Err) {
				t.Errorf("got: %v, want: %v", got, want)
			}
			return
		}
		if err != nil {
			t.Error(err)
		}
		if tc.Want == nil {
			if got, want := vec.String(), tc.In; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
			return
		}
	})
}
