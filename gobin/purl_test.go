package gobin

import (
	"context"
	"fmt"
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
					Filepath:  "/usr/local/bin/app",
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
					Filepath:  "/opt/agent/agent",
				},
				Repository: &Repository,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Align expected NormalizedVersion with ParsePURL behavior.
			if nv, err := ParseVersion(tc.ir.Package.Version); err == nil {
				tc.ir.Package.NormalizedVersion = nv
			}

			p, err := GeneratePURL(ctx, tc.ir)
			if err != nil {
				t.Fatalf("GeneratePURL: %v", err)
			}
			fmt.Println(p.String())
			got, err := ParsePURL(ctx, p)
			if err != nil {
				t.Fatalf("ParsePURL: %v", err)
			}
			if diff := cmp.Diff(tc.ir, got, purlCmp); diff != "" {
				t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

var purlCmp = cmp.Options{
	// Ignore PackageDB and Filepath as they are not currently used in the matching.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
}
