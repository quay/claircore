package dpkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestDistrolessLayer(t *testing.T) {
	tt := []struct {
		name string
		ref  test.LayerRef
		want []*claircore.Package
	}{
		{
			name: "debian11",
			ref: test.LayerRef{
				Registry: "gcr.io",
				Name:     "distroless/static-debian11",
				Digest:   `sha256:8fdb1fc20e240e9cae976518305db9f9486caa155fd5fc53e7b3a3285fe8a990`,
			},
			want: []*claircore.Package{
				{
					Name:      "base-files",
					Version:   "11.1+deb11u5",
					Kind:      types.BinaryPackage,
					Arch:      "amd64",
					PackageDB: "var/lib/dpkg/status.d/base",
				},
				{
					Name:      "netbase",
					Version:   "6.3",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/netbase",
				},
				{
					Name:      "tzdata",
					Version:   "2021a-1+deb11u8",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/tzdata",
				},
			},
		},
		{
			name: "debian12",
			ref: test.LayerRef{
				Registry: "gcr.io",
				Name:     "distroless/static-debian12",
				Digest:   `sha256:ef49c20a7b35aa995683f311510d35d77e203a2204f84de14a71a6d726e6af73`,
			},
			want: []*claircore.Package{
				{
					Name:      "tzdata",
					Version:   "2025b-0+deb12u2",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/tzdata",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := test.Logging(t)
			l := test.RealizeLayer(ctx, t, tc.ref)
			var s DistrolessScanner

			ps, err := s.Scan(ctx, l)
			if err != nil {
				t.Error(err)
			}
			if got, want := len(ps), len(tc.want); got != want {
				t.Errorf("checking length, got: %d, want: %d", got, want)
			}

			if !cmp.Equal(ps, tc.want) {
				t.Fatal(cmp.Diff(ps, tc.want))
			}
		})
	}
}
