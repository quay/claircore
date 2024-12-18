package cvss

import (
	"fmt"
	"testing"
)

func TestV2(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		Error[V2, V2Metric, *V2](t, LoadErrorFixture(t, "testdata/v2_error.list"))
	})
	t.Run("Roundtrip", func(t *testing.T) {
		Roundtrip[V2, V2Metric, *V2](t, LoadRoundtripFixture(t, "testdata/v2_roundtrip.list"))
	})
	t.Run("Score", func(t *testing.T) {
		Score[V2, V2Metric, *V2](t, LoadScoreFixture(t, "testdata/v2_score.list"))
	})

	t.Run("Unparse", func(t *testing.T) {
		tcs := []struct {
			Metric V2Metric
			Value  Value
			Want   string
		}{
			// Everything that does not have a direct single-byte mapping:
			{V2Exploitability, 'P', "POC"},
			{V2Exploitability, 'N', "ND"},
			{V2RemediationLevel, 'O', "OF"},
			{V2RemediationLevel, 'T', "TF"},
			{V2RemediationLevel, 'N', "ND"},
			{V2ReportConfidence, 'U', "UC"},
			{V2ReportConfidence, 'u', "UR"},
			{V2ReportConfidence, 'N', "ND"},
			{V2CollateralDamagePotential, 'M', "MH"},
			{V2CollateralDamagePotential, 'l', "LM"},
			{V2CollateralDamagePotential, 'X', "ND"},
			{V2TargetDistribution, 'X', "ND"},
			{V2ConfidentialityRequirement, 'N', "ND"},
			{V2IntegrityRequirement, 'N', "ND"},
			{V2AvailabilityRequirement, 'N', "ND"},
		}
		for _, tc := range tcs {
			t.Run(fmt.Sprintf("%v:%c", tc.Metric, tc.Value), func(t *testing.T) {
				got, want := UnparseV2Value(tc.Metric, tc.Value), tc.Want
				t.Logf("got: %q, want: %q", got, want)
				if got != want {
					t.Fail()
				}
			})
		}
	})
}
