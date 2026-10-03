package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	testpostgres "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/fixtures"
)

// TestKnownNotAffected tests that the acceptance framework correctly reports
// known_not_affected assertions from Red Hat VEX data.
//
// VEX documents are fetched at test time from the Red Hat security data server.
func TestKnownNotAffected(t *testing.T) {
	integration.Skip(t)
	integration.NeedDB(t)
	ctx := test.Logging(t)

	tt := []struct {
		Name     string
		Image    string
		VEXURL   string
		Expected []fixtures.ManifestRecord
	}{
		{
			// CVE-2024-24786 (protobuf infinite loop) is not applicable to the
			// MTA RHEL8 operator because the vulnerable Go protobuf code path is
			// not reachable. The VEX document asserts known_not_affected for the
			// amd64 variant via an OCI PURL, which the RHCC matcher resolves to
			// PackageNotVulnerable through AncestryPackage matching (Invert=true).
			Name:   "mta-rhel8-operator-protobuf",
			Image:  "quay.io/projectquay/clair-fixtures@sha256:1719cafe5b15c44bb1bb207bce1cc2a6ee7c1b097901d8fab61912ce298f40dd",
			VEXURL: "https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-24786.json",
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2024-24786",
					Product: "8Base-MTA-7.0:mta/mta-rhel8-operator@sha256:1719cafe5b15c44bb1bb207bce1cc2a6ee7c1b097901d8fab61912ce298f40dd_amd64",
					Status:  fixtures.StatusNotAffected,
				},
			},
		},
	}

	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)
	client := &http.Client{Timeout: 2 * time.Minute}

	auditor, err := NewClaircoreAuditor(ctx, t, &ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
		Platform:    "linux/amd64",
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			docs, err := FetchVEXDocs(ctx, client, []string{tc.VEXURL})
			if err != nil {
				t.Fatalf("fetch VEX: %v", err)
			}
			fix := &Fixture{
				Reference:    tc.Image,
				VEXDocuments: docs,
				Expected:     tc.Expected,
			}
			Run(ctx, t, auditor, []string{tc.Image}, WithFixture(fix))
		})
	}
}
