package alpine

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordAlpine(t *testing.T) {
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
					Name:      "busybox",
					Version:   "1.36.1-r0",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "apk:/busybox",
					Filepath:  "/bin/busybox",
					Source:    &claircore.Package{},
				},
				Distribution: &claircore.Distribution{
					Name:       "Alpine Linux",
					PrettyName: "Alpine Linux v3.18",
					Version:    "3.18",
					DID:        "alpine",
				},
			},
		},
		{
			name: "edge",
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:      "busybox",
					Version:   "1.36.1-r0",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "apk:/busybox",
					Filepath:  "/bin/busybox",
					Source:    &claircore.Package{},
				},
				Distribution: &claircore.Distribution{
					Name:       "Alpine Linux",
					PrettyName: "Alpine Linux edge",
					Version:    "edge",
					DID:        "alpine",
				},
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
			if diff := cmp.Diff([]*claircore.IndexRecord{tc.ir}, got, purlCmp); diff != "" {
				t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

var purlCmp = cmp.Options{
	// Ignore PackageDB and Filepath as they are not currently used in the matching.
	cmpopts.IgnoreFields(claircore.Package{}, "PackageDB", "Filepath"),
	// The version is what we save when indexing, the versionID is what we parse
	// from the vulnerability database. Neither are used in the matching, the DID,
	// DistributionName, and DistributionPrettyName are used.
	cmpopts.IgnoreFields(claircore.Distribution{}, "VersionID", "Version"),
}
