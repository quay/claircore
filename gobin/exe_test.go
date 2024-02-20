package gobin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestBin(t *testing.T) {
	ms, err := filepath.Glob("testdata/bin/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range ms {
		name := filepath.Base(n)
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			f, err := os.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var out []*claircore.Package
			if err := toPackages(ctx, &out, name, f); err != nil {
				t.Fatal(err)
			}
			for _, pkg := range out {
				t.Logf("%s@%s / %v", pkg.Name, pkg.Version, pkg.NormalizedVersion.String())
			}
		})
	}
}

var versionTestcases = []struct {
	name       string
	versionIn  string
	want       claircore.Version
	skipLegacy bool
}{
	{
		name:      "unchanged",
		versionIn: "1.2.30",
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 1, 2, 30, 0, 0, 0, 0, 0, 0},
		},
	},
	{
		name:      "with leading v",
		versionIn: "v1.2.30",
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 1, 2, 30, 0, 0, 0, 0, 0, 0},
		},
	},
	{
		name:      "with large version segment",
		versionIn: "v1.2.2023071210521689159162",
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 1, 2, 202307121, 0, 0, 0, 0, 0, 0},
		},
		skipLegacy: true,
	},
	{
		name:      "typical",
		versionIn: "v0.0.0-20200804184101-5ec99f83aff1",
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	},
	{
		name:      "missing patch",
		versionIn: `1.18`,
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 1, 18, 0, 0, 0, 0, 0, 0, 0},
		},
	},
	{
		name:      "incompatible",
		versionIn: "v24.0.7+incompatible",
		want: claircore.Version{
			Kind: "semver",
			V:    [...]int32{0, 24, 0, 7, 0, 0, 0, 0, 0, 0},
		},
	},
}

func TestParseVersion(t *testing.T) {
	// Run testcases on the legacy and new parsing logic
	// to test symmetry.

	for _, tt := range versionTestcases {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.skipLegacy {
				// legacy
				ver, err := semver.NewVersion(tt.versionIn)
				if err != nil {
					t.Fatal("error creating new semver:", err)
				}
				gotLegacy := claircore.FromSemver(ver)
				if !cmp.Equal(tt.want, gotLegacy) {
					t.Error("unexpected legacy parsing", cmp.Diff(tt.want, gotLegacy))
				}
			}

			// new
			got, err := ParseVersion(tt.versionIn)
			if err != nil {
				t.Fatal("got error parsing version:", err)
			}
			if !cmp.Equal(tt.want, got) {
				t.Error(cmp.Diff(tt.want, got))
			}
		})
	}
}
