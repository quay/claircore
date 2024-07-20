package cvss

import (
	"testing"
)

func TestV3(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		tcs := []ErrorTestcase{
			{Vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
			{Vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1", Error: true},
			{Vector: "CVSS3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A-N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/X:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:X/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:X/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:X/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:X/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:X/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:X/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Error: true},
			{Vector: "CVSS:3.1/CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Error: true},
			{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/AV:X", Error: true},
			{Vector: "CVSS:3.3", Error: true},
		}
		Error[V3, V3Metric, *V3](t, tcs)
	})

	t.Run("Roundtrip", func(t *testing.T) {
		vecs := []string{
			"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",          // Zero metrics
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",          // CVE-2015-8252
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",          // CVE-2013-1937
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",          // CVE-2013-0375
			"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",          // CVE-2014-3566
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",          // CVE-2012-1516
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",          // CVE-2012-0384
			"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",          // CVE-2015-1098
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",          // CVE-2014-0160
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",          // CVE-2014-6271
			"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",          // CVE-2008-1447
			"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",          // CVE-2014-2005
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",          // CVE-2010-0467
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",          // CVE-2012-1342
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",          // CVE-2014-9253
			"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",          // CVE-2009-0658
			"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",          // CVE-2011-1265
			"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",          // CVE-2014-2019
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",          // CVE-2015-0970
			"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",          // CVE-2014-0224
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",          // CVE-2012-5376
			"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/RL:X", // From Example
		}
		Roundtrip[V3, V3Metric, *V3](t, vecs)
	})
	t.Run("Score", func(t *testing.T) {
		t.Run("3.0", func(t *testing.T) {
			tcs := []ScoreTestcase{
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", Score: 6.1}, // CVE-2013-1937

				{Vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", Score: 6.4}, // CVE-2013-0375
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", Score: 3.1}, // CVE-2014-3566
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", Score: 9.9}, // CVE-2012-1516
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", Score: 7.2}, // CVE-2012-0384
				{Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2015-1098
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Score: 7.5}, // CVE-2014-0160
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8}, // CVE-2014-6271
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", Score: 6.8}, // CVE-2008-1447
				{Vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 6.8}, // CVE-2014-2005
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", Score: 5.8}, // CVE-2010-0467
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", Score: 5.8}, // CVE-2012-1342
				{Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", Score: 9.3}, // CVE-2013-6014
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", Score: 9.0}, // CVE-2019-7551
				{Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2009-0658
				{Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2011-1265
				{Vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", Score: 4.6}, // CVE-2014-2019
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2015-0970
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 7.4}, // CVE-2014-0224
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", Score: 9.6}, // CVE-2012-5376
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2016-1645
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", Score: 6.8}, // CVE-2016-0128
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.5}, // CVE-2016-2118
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", Score: 6.1}, // CVE-2017-5942
				{Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2018-18913
				{Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", Score: 8.6}, // CVE-2016-5558
				{Vector: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", Score: 8.2}, // CVE-2016-5729
				{Vector: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", Score: 6.0}, // CVE-2015-2890
				{Vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 7.6}, // CVE-2018-3652
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.5}, // CVE-2019-0884 (IE)
				{Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", Score: 4.2}, // CVE-2019-0884 (Edge)
			}
			Score[V3, V3Metric, *V3](t, tcs)
		})
		t.Run("3.1", func(t *testing.T) {
			tcs := []ScoreTestcase{
				{Vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Score: 0}, // Zero metrics
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:N", Score: 0}, // Zero metrics

				{Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", Score: 6.4}, // CVE-2013-0375
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", Score: 3.1}, // CVE-2014-3566
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", Score: 9.9}, // CVE-2012-1516
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", Score: 7.2}, // CVE-2012-0384
				{Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2015-1098
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Score: 7.5}, // CVE-2014-0160
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8}, // CVE-2014-6271
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", Score: 6.8}, // CVE-2008-1447
				{Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 6.8}, // CVE-2014-2005
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", Score: 5.8}, // CVE-2010-0467
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", Score: 5.8}, // CVE-2012-1342
				{Vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", Score: 9.3}, // CVE-2013-6014
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", Score: 9.0}, // CVE-2019-7551
				{Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2009-0658
				{Vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2011-1265
				{Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", Score: 4.6}, // CVE-2014-2019
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2015-0970
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 7.4}, // CVE-2014-0224
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", Score: 9.6}, // CVE-2012-5376
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 8.8}, // CVE-2016-1645
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", Score: 6.8}, // CVE-2016-0128
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.5}, // CVE-2016-2118
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", Score: 6.1}, // CVE-2017-5942
				{Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.8}, // CVE-2018-18913
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", Score: 8.6}, // CVE-2016-5558
				{Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", Score: 8.2}, // CVE-2016-5729
				{Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", Score: 6.0}, // CVE-2015-2890
				{Vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 7.6}, // CVE-2018-3652
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: 7.5}, // CVE-2019-0884 (IE)
				{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", Score: 4.2}, // CVE-2019-0884 (Edge)

				{Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/RL:X", Score: 3.7},       // From spec example
				{Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/CR:H/IR:H/AR:H", Score: 4.8}, // made up
			}
			Score[V3, V3Metric, *V3](t, tcs)
		})
	})
}
