package ubuntu

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/claircore"
)

func TestRoundTripIndexRecordDebian(t *testing.T) {
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
					Name:      "bash",
					Version:   "5.1.8-6",
					Arch:      "x86_64",
					Kind:      claircore.BINARY,
					PackageDB: "deb:/var/lib/dpkg/status",
					Source:    &claircore.Package{},
				},
				Distribution: &claircore.Distribution{
					Name:            "Ubuntu",
					DID:             "ubuntu",
					VersionID:       "24.04",
					PrettyName:      "Ubuntu 24.04",
					VersionCodeName: "noble",
					Version:         "24.04 (Noble)",
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
			fmt.Println(p.String())
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
	// The distribution that we can decipher from the PURL only has the fields that
	// are used in the matching; DID, Name and VersionID.
	cmpopts.IgnoreFields(claircore.Distribution{}, "VersionCodeName", "Version", "PrettyName"),
}
