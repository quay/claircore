package acceptance_test

import (
	"context"
	"io"
	"iter"
	"net/http"
	"testing"

	"github.com/quay/claircore/test/acceptance"
	"github.com/quay/claircore/toolkit/fixtures"
)

// ExampleAuditor demonstrates how to implement a custom Auditor.
// This file exists to ensure the example in the documentation compiles.
type ExampleAuditor struct{}

// Compile-time interface check.
var _ acceptance.Auditor = (*ExampleAuditor)(nil)

func (a *ExampleAuditor) Audit(ctx context.Context, t testing.TB, ref string, csafDocs iter.Seq[io.Reader]) ([]acceptance.Result, error) {
	// 1. Index the image at 'ref' to get packages/SBOMs
	// packages, err := a.indexImage(ctx, ref)

	// 2. Parse the CSAF documents
	for r := range csafDocs {
		_ = r // Parse CSAF and match against packages
	}

	// 3. Return results in the expected format, the framework does the comparison.
	return nil, nil
}

func Example() {
	ctx := context.Background()
	t := &testing.T{}
	auditor := &ExampleAuditor{}

	acceptance.Run(ctx, t, auditor, []string{
		"quay.io/projectquay/clair-fixtures:python-test",
	})
}

// ExampleWithFixture demonstrates building a fixture from live VEX URLs
// using [acceptance.FetchVEXDocs] and [acceptance.WithFixture], without
// storing VEX documents as OCI referrers.
func ExampleWithFixture() {
	ctx := context.Background()
	t := &testing.T{}
	auditor := &ExampleAuditor{}

	docs, err := acceptance.FetchVEXDocs(ctx, http.DefaultClient, []string{
		"https://security.example.com/advisories/CVE-2024-1234.json",
	})
	if err != nil {
		t.Fatal(err)
	}

	fix := &acceptance.Fixture{
		Reference:    "registry.example.com/namespace/image@sha256:abc123...",
		VEXDocuments: docs,
		Expected: []fixtures.ManifestRecord{
			{ID: "CVE-2024-1234", Product: "mypackage-1.2.3", Status: fixtures.StatusAffected},
		},
	}

	acceptance.Run(ctx, t, auditor, nil, acceptance.WithFixture(fix))
}
