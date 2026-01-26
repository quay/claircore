package oracle

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordOracle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "ol9",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1.8-6.el9",
					Arch:    "x86_64",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Distribution: nineDist,
			},
		},
		{
			name: "ol7",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "coreutils",
					Version: "8.22-24.oe1",
					Arch:    "aarch64",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Distribution: sevenDist,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GeneratePURL: %v", err)
			}
			t.Logf("generated PURL: %s", p.String())
			got, err := ParsePURL(ctx, p)
			if err != nil {
				t.Fatalf("ParsePURL: %v", err)
			}
			if diff := cmp.Diff(got, []*claircore.IndexRecord{tc.ir}); diff != "" {
				t.Fatalf("round-trip mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestGeneratePURL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name string
		ir   *claircore.IndexRecord
		want packageurl.PackageURL
	}{
		{
			name: "basic-ol9",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1.8-6.el9",
					Arch:    "x86_64",
				},
				Distribution: releaseToDist(Nine),
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: PURLNamespace,
				Name:      "bash",
				Version:   "5.1.8-6.el9",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "x86_64"},
					{Key: "distro", Value: "oracle-9"},
				},
			},
		},
		{
			name: "basic-ol7",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "coreutils",
					Version: "8.22-24.oe1",
					Arch:    "aarch64",
				},
				Distribution: releaseToDist(Seven),
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: PURLNamespace,
				Name:      "coreutils",
				Version:   "8.22-24.oe1",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "aarch64"},
					{Key: "distro", Value: "oracle-7"},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GeneratePURL: %v", err)
			}
			t.Logf("generated PURL: %s", got.String())
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("purl mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
