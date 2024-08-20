package cvss

import (
	"fmt"
	"testing"
)

func TestV2(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		tcs := []ErrorTestcase{
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C"},
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H"},
			{Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C", Error: true},
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N", Error: true},
			{Vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H", Error: true},
			{Vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/E:F", Error: true},
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/Au:N", Error: true},
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:", Error: true},
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C?notaurl=1", Error: true},
			{Vector: "AV:A/AC:L/Au:N/A:C/I:C/C:C", Error: true},
		}
		Error[V2, V2Metric, *V2](t, tcs)
	})
	t.Run("Roundtrip", func(t *testing.T) {
		vecs := []string{
			"AV:N/AC:L/Au:N/C:N/I:N/A:C",                                                // CVE-2002-0392
			"AV:N/AC:L/Au:N/C:C/I:C/A:C",                                                // CVE-2003-0818
			"AV:L/AC:H/Au:N/C:C/I:C/A:C",                                                // CVE-2003-0062
			"AV:L/AC:H/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",       // CVE-2002-0392
			"AV:L/AC:H/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:UR/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND", // made up
			"AV:L/AC:H/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:UR/CDP:LM/TD:ND/CR:ND/IR:ND/AR:ND", // made up
		}
		Roundtrip[V2, V2Metric, *V2](t, vecs)
	})
	t.Run("Score", func(t *testing.T) {
		tcs := []ScoreTestcase{
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C", Score: 7.8},                                            // CVE-2002-0392
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C", Score: 6.4},                             // CVE-2002-0392
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:H", Score: 0.0},   // CVE-2002-0392
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H", Score: 9.2},   // CVE-2002-0392
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Score: 10.0},                                           // CVE-2003-0818
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C", Score: 8.3},                             // CVE-2003-0818
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:L", Score: 0.0},   // CVE-2003-0818
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L", Score: 9.0},   // CVE-2003-0818
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C", Score: 6.2},                                            // CVE-2003-0062
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C", Score: 4.9},                           // CVE-2003-0062
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:M", Score: 0.0}, // CVE-2003-0062
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M", Score: 7.5}, // CVE-2003-0062
		}
		Score[V2, V2Metric, *V2](t, tcs)
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
