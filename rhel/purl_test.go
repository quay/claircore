package rhel

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRoundTripIndexRecordRPM(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "basic-with-module-and-distro",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1.8-6",
					Arch:    "x86_64",
					Module:  "bash:5.1",
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/a:redhat:enterprise_linux:8"),
					Key:  repositoryKey,
					Name: "cpe:2.3:a:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
				},
				Distribution: &claircore.Distribution{
					Name: "rhel",
				},
			},
		},
		{
			name: "epoch-version-release-no-module",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "coreutils",
					Version: "1:9.1-3",
					Arch:    "x86_64",
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/a:redhat:enterprise_linux:9::baseos"),
					Key:  repositoryKey,
					Name: "cpe:2.3:a:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
				},
			},
		},
		{
			name: "different-product-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "openssl",
					Version: "3.0.7-16",
					Arch:    "aarch64",
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/a:redhat:enterprise_linux:9::appstream"),
					Key:  repositoryKey,
					Name: "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := GenerateRPMPURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateRPMPURL: %v", err)
			}
			got, err := ParseRPMPURL(ctx, p)
			if err != nil {
				t.Fatalf("ParseRPMPURL: %v", err)
			}
			if diff := cmp.Diff(got, []*claircore.IndexRecord{tc.ir}, purlCmp); diff != "" {
				t.Fatalf("round-trip mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestGenerateRPMPURL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name string
		ir   *claircore.IndexRecord
		want packageurl.PackageURL
	}{
		{
			name: "basic",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "5.1.8-6",
					Arch:    "x86_64",
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/a:redhat:enterprise_linux:8"),
					Key:  repositoryKey,
					Name: "cpe:2.3:a:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
					URI:  "repoid=rhel-8-for-x86_64-baseos-rpms",
				},
			},
			want: packageurl.PackageURL{
				Type:      "rpm",
				Namespace: "redhat",
				Name:      "bash",
				Version:   "5.1.8-6",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "x86_64"},
					{Key: "repository_cpes", Value: "cpe:2.3:a:redhat:enterprise_linux:8:*:*:*:*:*:*:*"},
					{Key: "repository_id", Value: "rhel-8-for-x86_64-baseos-rpms"},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateRPMPURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateRPMPURL: %v", err)
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("purl mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

var purlCmp = cmp.Options{
	// Ignore Distribution field as there isn't currently a serialized format
	// and it is not currently used in the matching.
	cmpopts.IgnoreFields(claircore.IndexRecord{}, "Distribution"),
	cmpopts.EquateComparable(),
	cmpCPE,
}

var cmpCPE = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".CPE" },
	cmp.Comparer(func(a, b cpe.WFN) bool { return a.String() == b.String() }),
)
