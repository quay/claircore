package java

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordJava(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name string
		ir   *claircore.IndexRecord
	}{
		{
			name: "basic",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.commons:commons-lang3",
					Version: "3.12.0",
					Kind:    claircore.BINARY,
					Source:  &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "different-version",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.fasterxml.jackson.core:jackson-databind",
					Version: "2.17.1",
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
					Name:    "org.slf4j:slf4j-api",
					Version: "2.0.12",
				},
			},
			want: packageurl.PackageURL{
				Type:      PURLType,
				Namespace: "org.slf4j",
				Name:      "slf4j-api",
				Version:   "2.0.12",
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
	// Ignore fields that are not part of the PURL round-trip for Java.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
