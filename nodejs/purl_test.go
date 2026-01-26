package nodejs

import (
	"context"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordNodeJS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name    string
		ir      *claircore.IndexRecord
		wantErr bool
	}{
		{
			name: "express",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "express",
					Version: "4.18.2",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "lodash",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "lodash",
					Version: "4.17.21",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "bad-version",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "left-pad",
					Version: "not-a-version",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Align expected NormalizedVersion with GeneratePURL/ParsePURL behaviour.
			if v, err := semver.NewVersion(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = claircore.FromSemver(v)
			}

			p, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GeneratePURL: %v", err)
			}
			t.Logf("generated PURL: %s", p.String())

			got, err := ParsePURL(ctx, p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePURL unexpected error: %v", err)
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
			name: "basic",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "express",
					Version: "4.18.2",
				},
			},
			want: packageurl.PackageURL{
				Type:    PURLType,
				Name:    "express",
				Version: "4.18.2",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure NormalizedVersion is set since GeneratePURL uses it.
			if v, err := semver.NewVersion(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = claircore.FromSemver(v)
			}
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

var purlCmp = cmp.Options{
	// Ignore fields not relevant to PURL round-trip for Node.js.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
