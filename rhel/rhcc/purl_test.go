package rhcc

import (
	"context"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRoundTripIndexRecordOCI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "goldrepo-no-container-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:              "ubi",
					Version:           "v9.3.1",
					NormalizedVersion: claircore.FromSemver(semver.MustParse("v9.3.1")),
					Arch:              "x86_64",
					RepositoryHint:    "rhcc",
					Source:            &claircore.Package{},
				},
				Repository: &GoldRepo,
			},
		},
		{
			name: "with-container-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:              "ubi-micro",
					Version:           "v9.3.1",
					NormalizedVersion: claircore.FromSemver(semver.MustParse("v9.3.1")),
					Arch:              "x86_64",
					RepositoryHint:    "rhcc",
					Source:            &claircore.Package{},
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::baseos"),
					Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
					Key:  RepositoryKey,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := GenerateOCIPURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateOCIPURL: %v", err)
			}
			t.Logf("generated PURL: %s", p.String())
			got, err := ParseOCIPURL(ctx, p)
			if err != nil {
				t.Fatalf("ParseOCIPURL: %v", err)
			}
			if diff := cmp.Diff(got, []*claircore.IndexRecord{tc.ir}, purlCmp); diff != "" {
				t.Fatalf("round-trip mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestGenerateOCIPURL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name string
		ir   *claircore.IndexRecord
		want packageurl.PackageURL
	}{
		{
			name: "basic-goldrepo",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "ubi",
					Version: "v9.3.1",
					Arch:    "amd64",
				},
				Repository: &GoldRepo,
			},
			want: packageurl.PackageURL{
				Type:    PURLType,
				Name:    "ubi",
				Version: "v9.3.1",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "amd64"},
					{Key: "tag", Value: "v9.3.1"},
				},
			},
		},
		{
			name: "with-container-cpe",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "ubi",
					Version: "v9.3.1",
					Arch:    "amd64",
				},
				Repository: &claircore.Repository{
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::baseos"),
					Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
					Key:  RepositoryKey,
				},
			},
			want: packageurl.PackageURL{
				Type:    PURLType,
				Name:    "ubi",
				Version: "v9.3.1",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "amd64"},
					{Key: "tag", Value: "v9.3.1"},
					{Key: "container_cpe", Value: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateOCIPURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GenerateOCIPURL: %v", err)
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
	cmpCPE,
}

var cmpCPE = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".CPE" },
	cmp.Comparer(func(a, b cpe.WFN) bool { return a.String() == b.String() }),
)
