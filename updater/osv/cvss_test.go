package osv

import (
	"context"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/zlog"
)

// Test harness adapted from https://github.com/goark/go-cvss/blob/634a87a6c9dd62c8d061d04133e022627cc0e1f8/v3/base/base_test.go

func TestCVSS(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		ctx := zlog.Test(context.Background(), t)
		tcs := []struct {
			vector string
			err    bool
		}{
			{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
			{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
			{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
			{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: true},
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
		}
		for _, tc := range tcs {
			_, err := fromCVSS3(ctx, tc.vector)
			t.Logf("in: %q, got: %v", tc.vector, err)
			if (err != nil) != tc.err {
				t.Error(err)
			}
		}
	})

	t.Run("Severity", func(t *testing.T) {
		ctx := zlog.Test(context.Background(), t)
		tcs := []struct {
			vector   string
			severity claircore.Severity
		}{
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
		}

		for _, tc := range tcs {
			sev, err := fromCVSS3(ctx, tc.vector)
			t.Logf("in: %q, got: %v", tc.vector, sev)
			if err != nil {
				t.Error(err)
			}
			if got, want := sev, tc.severity; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		}
	})

	t.Run("V2", func(t *testing.T) {
		tcs := []struct {
			vector   string
			severity claircore.Severity
		}{
			{vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C", severity: claircore.High},   // CVE-2002-0392
			{vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", severity: claircore.High},   // CVE-2003-0818
			{vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C", severity: claircore.Medium}, // CVE-2003-0062
		}

		for _, tc := range tcs {
			sev, err := fromCVSS2(tc.vector)
			t.Logf("in: %q, got: %v", tc.vector, sev)
			if err != nil {
				t.Error(err)
			}
			if got, want := sev, tc.severity; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		}
	})
}
