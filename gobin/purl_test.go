package gobin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordGobin(t *testing.T) {
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
					Name:      "github.com/example/app",
					Version:   "v1.2.3",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "go:/usr/local/bin/app",
					Source:    &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "different-arch",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:      "github.com/example/agent",
					Version:   "v0.9.0",
					Arch:      "aarch64",
					Kind:      claircore.BINARY,
					PackageDB: "go:/opt/agent/agent",
					Source:    &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
		{
			name: "stdlib-no-subpath",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:      "stdlib",
					Version:   "v1.0.0",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "go:/usr/local/bin/go",
					Source:    &claircore.Package{},
				},
				Repository: &Repository,
			},
		},

		{
			name: "subpath",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:      "go.opentelemetry.io/otel/exporters/jaeger",
					Version:   "v1.15.1",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "go:/usr/local/bin/app",
					Source:    &claircore.Package{},
				},
				Repository: &Repository,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Align expected NormalizedVersion with ParsePURL behaviour.
			if nv, err := ParseVersion(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = nv
			}

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

var purlCmp = cmp.Options{
	// Ignore PackageDB and Filepath as they are not currently used in the matching.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
