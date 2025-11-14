package aws

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRoundTripIndexRecordAWS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "amzn2",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "curl",
					Version: "7.79.1-2.amzn2.0.2",
					Arch:    "x86_64",
					Kind:    claircore.BINARY,
				},
				Distribution: &claircore.Distribution{
					Name:       "Amazon Linux AMI",
					VersionID:  "2018.03",
					DID:        "amzn",
					Version:    "2018.03",
					PrettyName: "Amazon Linux AMI 2018.03",
					CPE:        cpe.MustUnbind("cpe:/o:amazon:linux:2018.03:ga"),
				},
			},
		},
		{
			name: "amzn2023",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1.16-6.amzn2023.0.4",
					Arch:    "aarch64",
					Kind:    claircore.BINARY,
				},
				Distribution: &claircore.Distribution{
					Name:       "Amazon Linux",
					VersionID:  "2023",
					DID:        "amzn",
					Version:    "2023",
					PrettyName: "Amazon Linux 2023",
					CPE:        cpe.MustUnbind("cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*"),
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
			name: "amzn2-basic",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "curl",
					Version: "7.79.1-2.amzn2.0.2",
					Arch:    "x86_64",
				},
				Distribution: &claircore.Distribution{
					Name:      "Amazon Linux",
					VersionID: "2023",
					Version:   "2023",
					DID:       "amzn",
				},
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: PURLNamespace,
				Name:      "curl",
				Version:   "7.79.1-2.amzn2.0.2",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "x86_64"},
					{Key: "distro", Value: "amzn-2023"},
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
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("purl mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
