package osv

import (
	"testing"

	"github.com/quay/claircore"
)

func TestCVSS(t *testing.T) {
	var tests = map[string][]struct {
		vector   string
		err      bool
		severity claircore.Severity
	}{
		"v2": {
			{vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C", severity: claircore.High},     // CVE-2002-0392
			{vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", severity: claircore.Critical}, // CVE-2003-0818
			{vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C", severity: claircore.Medium},   // CVE-2003-0062
		},
		"v3": {
			{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", severity: claircore.Negligible},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", severity: claircore.Negligible},
			{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1", err: true},
			{vector: "CVSS3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A-N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/X:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:X/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:X/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:X/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:X/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:X/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:X/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", severity: claircore.Negligible}, // Zero metrics
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", severity: claircore.High},       // CVE-2015-8252
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", severity: claircore.Medium},     // CVE-2013-1937
			{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", severity: claircore.Medium},     // CVE-2013-0375
			{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", severity: claircore.Low},        // CVE-2014-3566
			{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", severity: claircore.Critical},   // CVE-2012-1516
			{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", severity: claircore.High},       // CVE-2012-0384
			{vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", severity: claircore.High},       // CVE-2015-1098
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", severity: claircore.High},       // CVE-2014-0160
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: claircore.Critical},   // CVE-2014-6271
			{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", severity: claircore.Medium},     // CVE-2008-1447
			{vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: claircore.Medium},     // CVE-2014-2005
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", severity: claircore.Medium},     // CVE-2010-0467
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", severity: claircore.Medium},     // CVE-2012-1342
			{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", severity: claircore.Medium},     // CVE-2014-9253
			{vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", severity: claircore.High},       // CVE-2009-0658
			{vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: claircore.High},       // CVE-2011-1265
			{vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", severity: claircore.Medium},     // CVE-2014-2019
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", severity: claircore.High},       // CVE-2015-0970
			{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", severity: claircore.High},       // CVE-2014-0224
			{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", severity: claircore.Critical},   // CVE-2012-5376
		},
		"v4": {
			// The following test cases comes from the CVSS v4.0 Examples (last extract: 9th Nov., 2023)
			{vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", severity: claircore.High},         // CVE-2022-41741
			{vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", severity: claircore.High},         // CVE-2020-3549
			{vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", severity: claircore.High},         // CVE-2023-3089
			{vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", severity: claircore.Medium},       // CVE-2021-44714
			{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", severity: claircore.Medium},       // CVE-2022-21830
			{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", severity: claircore.Medium},       // CVE-2022-22186
			{vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", severity: claircore.Medium},       // CVE-2023-21989
			{vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", severity: claircore.Critical},     // CVE-2020-3947
			{vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D", severity: claircore.High}, // CVE-2023-30560
			{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", severity: claircore.High},     // CVE-2014-0160 aka Heartbleed
			{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", severity: claircore.Critical}, // CVE-2021-44228 aka log4shell
			{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", severity: claircore.Critical}, // CVE-2014-6271 aka Shellshock
			{vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", severity: claircore.Medium},       // CVE-2013-6014
			{vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", severity: claircore.Critical}, // CVE-2016-5729
			{vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", severity: claircore.High},     // CVE-2015-2890
			{vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", severity: claircore.High},         // CVE-2018-3652
			// ... following examples are provided for guidance on scoring common vulnerabilities classes
		},
	}

	for ver, vtc := range tests {
		t.Run(ver, func(t *testing.T) {
			for _, tc := range vtc {
				sev, err := fromCVSS(tc.vector)
				if (err != nil) != tc.err {
					t.Errorf("Expected error: %t, got %v", tc.err, err)
				}
				if sev != tc.severity {
					t.Errorf("For vector %s, got severity %v, want %v", tc.vector, sev, tc.severity)
				}
			}
		})
	}
}
