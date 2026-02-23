package suse

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRoundTripIndexRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "opensuse-leap-with-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "zlib",
					Version: "1.2.11-150500.59.68.1",
					Arch:    "x86_64",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Distribution: &claircore.Distribution{
					CPE:        cpe.MustUnbind("cpe:2.3:o:opensuse:leap:15.5"),
					Name:       "openSUSE Leap",
					VersionID:  "15.5",
					Version:    "15.5",
					DID:        "opensuse-leap",
					PrettyName: "openSUSE Leap 15.5",
				},
			},
		},
		{
			name: "sles-fallback-distro",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1-150300.51.1",
					Arch:    "aarch64",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Distribution: &claircore.Distribution{
					Name:       "SLES",
					VersionID:  "12",
					Version:    "12",
					DID:        "sles",
					PrettyName: "SUSE Linux Enterprise Server 12",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateRPMPURL: %v", err)
			}
			t.Logf("generated PURL: %s", p.String())
			got, err := ParsePURL(ctx, p)
			if err != nil {
				t.Fatalf("ParseRPMPURL: %v", err)
			}
			if diff := cmp.Diff(got, []*claircore.IndexRecord{tc.ir}, purlCmp); diff != "" {
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
			name: "with-distro-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "zlib",
					Version: "1.2.11-150500.59.68.1",
					Arch:    "x86_64",
				},
				Distribution: &claircore.Distribution{
					CPE:       cpe.MustUnbind("cpe:2.3:o:opensuse:leap:15.5"),
					Name:      "openSUSE Leap",
					VersionID: "15.5",
					DID:       "opensuse",
				},
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: PURLNamespace,
				Name:      "zlib",
				Version:   "1.2.11-150500.59.68.1",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "x86_64"},
					{Key: "distro_cpe", Value: "cpe:2.3:o:opensuse:leap:15.5:*:*:*:*:*:*:*"},
					{Key: "distro", Value: "opensuse-15.5"},
				},
			},
		},
		{
			name: "fallback-distro-qualifier",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1-150300.51.1",
					Arch:    "aarch64",
				},
				Distribution: &claircore.Distribution{
					Name:      "SUSE Linux Enterprise Server",
					VersionID: "12",
					DID:       "suse",
				},
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: PURLNamespace,
				Name:      "bash",
				Version:   "5.1-150300.51.1",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "aarch64"},
					{Key: "distro", Value: "suse-12"},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateRPMPURL: %v", err)
			}
			t.Logf("generated PURL: %s", got.String())
			if !cmp.Equal(got, tc.want, purlCmp) {
				t.Errorf("purl mismatch:\n%s", cmp.Diff(got, tc.want, purlCmp))
			}
		})
	}
}

var purlCmp = cmp.Options{
	// Ignore Distribution field differences for round-trip; only assert package fields.
	cmpopts.IgnoreFields(claircore.Distribution{}, "PrettyName", "CPE"),
	cmpopts.SortSlices(func(a, b packageurl.Qualifier) int {
		return strings.Compare(a.Key, b.Key)
	}),
}
