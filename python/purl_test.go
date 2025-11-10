package python

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/pep440"
)

func TestRoundTripIndexRecordPython(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name    string
		ir      *claircore.IndexRecord
		wantErr bool
	}{
		{
			name: "urllib3",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "urllib3",
					Version: "2.2.1",
					Kind:    claircore.BINARY,
				},
				Repository: &Repository,
			},
		},
		{
			name: "django",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "django",
					Version: "1.11.1",
					Kind:    claircore.BINARY,
				},
				Repository: &Repository,
			},
		},
		{
			name: "bad-version",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "django",
					Version: "something-invalid",
					Kind:    claircore.BINARY,
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
			// This helps the testcases stay simple.
			if v, err := pep440.Parse(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = v.Version()
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
					Name:    "requests",
					Version: "2.31.0",
				},
			},
			want: packageurl.PackageURL{
				Type:    PURLType,
				Name:    "requests",
				Version: "2.31.0",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure NormalizedVersion is set since GeneratePURL uses it.
			if v, err := pep440.Parse(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = v.Version()
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
	// Ignore fields not relevant to PURL round-trip for Python.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
