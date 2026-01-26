package ruby

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordRuby(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "rails",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "rails",
					Version: "6.1.0",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "rack",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "rack",
					Version: "2.2.8",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
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
					Name:    "rails",
					Version: "6.1.0",
				},
			},
			want: packageurl.PackageURL{
				Type:    PURLType,
				Name:    "rails",
				Version: "6.1.0",
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

var purlCmp = cmp.Options{
	// Ignore fields not relevant to PURL round-trip for Ruby.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
