package cvss

import "testing"

func TestV2(t *testing.T) {
	t.Run("Roundtrip", func(t *testing.T) {
		vecs := []string{
			"AV:N/AC:L/Au:N/C:N/I:N/A:C", // CVE-2002-0392
			"AV:N/AC:L/Au:N/C:C/I:C/A:C", // CVE-2003-0818
			"AV:L/AC:H/Au:N/C:C/I:C/A:C", // CVE-2003-0062
		}
		Roundtrip[V2, V2Metric, *V2](t, vecs)
	})
	t.Run("Score", func(t *testing.T) {
		tcs := []ScoreTestcase{
			{Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C", Score: 7.8},  // CVE-2002-0392
			{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Score: 10.0}, // CVE-2003-0818
			{Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C", Score: 6.2},  // CVE-2003-0062
		}
		Score[V2, V2Metric, *V2](t, tcs)
	})
}
