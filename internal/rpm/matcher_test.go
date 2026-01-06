package rpm

import (
	"errors"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

func TestMatchVulnerable(t *testing.T) {
	record := func(v string) *claircore.IndexRecord {
		return &claircore.IndexRecord{Package: &claircore.Package{Version: v, Arch: "x86_64"}}
	}
	tcs := []struct {
		Name          string
		Record        *claircore.IndexRecord
		Vulnerability *claircore.Vulnerability
		Want          bool
		Err           error
	}{
		{
			Name:          "Infinite",
			Record:        record("0:1.2.3-4"),
			Vulnerability: &claircore.Vulnerability{Package: new(claircore.Package)},
			Want:          true,
		},
		{
			Name:   "InfiniteWrongArch",
			Record: record("0:1.2.3-4"),
			Vulnerability: &claircore.Vulnerability{
				Package:       &claircore.Package{Arch: "aarch64"},
				ArchOperation: claircore.OpEquals,
			},
			Want: false,
		},
		{
			Name:   "BadRecordVersion",
			Record: record("1.2.3"), // Not an EVR
			Err:    rpmver.ErrParse,
		},
		{
			Name:   "BadVulnerabilityVersion",
			Record: record("1.2.3-4"),
			Vulnerability: &claircore.Vulnerability{
				FixedInVersion: "2.0",
			},
			Err: rpmver.ErrParse,
		},
		{
			Name:   "FixedIn",
			Record: record("1.2.3-4"),
			Vulnerability: &claircore.Vulnerability{
				FixedInVersion: "1.2.3-4",
			},
			Want: false,
		},
		{
			Name:   "Package",
			Record: record("1.2.3-4"),
			Vulnerability: &claircore.Vulnerability{
				Package: &claircore.Package{Version: "1.2.3-4"},
			},
			Want: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := t.Context()
			got, err := MatchVulnerable(ctx, tc.Record, tc.Vulnerability)
			if !errors.Is(err, tc.Err) {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tc.Want {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
	}
}
