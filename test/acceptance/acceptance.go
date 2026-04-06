// Package acceptance provides a testing framework for vulnerability auditors.
// It loads test fixtures from OCI registries using the Referrers API,
// runs auditors against them, and compares results with the expected fixture
package acceptance

import (
	"bytes"
	"context"
	"io"
	"iter"
	"testing"

	"github.com/quay/claircore/toolkit/fixtures"
)

// Auditor is the interface that vulnerability auditors must implement.
type Auditor interface {
	// Audit analyses the image at ref using the provided CSAF documents
	// and returns vulnerability findings.
	Audit(ctx context.Context, t testing.TB, ref string, csafDocs iter.Seq[io.Reader]) ([]Result, error)
}

// Result is a single vulnerability finding from a scanner.
type Result struct {
	// TrackingID is the CSAF trackingID.
	TrackingID string
	// ProductID is the CSAF productID from the product tree.
	ProductID string
	// Status is the scanner's determination.
	Status fixtures.VulnerabilityStatus
	// Package is the matched package name@version for debugging.
	Package string
}

// Fixture is a loaded test fixture from an OCI registry.
type Fixture struct {
	// Reference is the OCI reference (e.g., "registry.io/repo:tag").
	Reference string
	// Manifest is the digest of the OCI manifest.
	Manifest string
	// VEXDocuments contains the CSAF/VEX documents for vulnerability matching.
	VEXDocuments [][]byte
	// Expected is the parsed vulnerability manifest (expected output).
	Expected []fixtures.ManifestRecord
}

// Comparison is the result of comparing expected vs actual scanner results.
type Comparison struct {
	// Fixture is the reference that was tested.
	Fixture string
	// Matches are results that matched expectations.
	Matches []Match
	// Mismatches are results with the wrong status.
	Mismatches []Mismatch
	// Misses are expected results that the scanner did not report.
	Misses []fixtures.ManifestRecord
	// Extras are results reported by the scanner but not in the fixture.
	// These do not cause test failure (scanner may find more than fixture defines).
	// TODO (crozzy): Maybe a strict mode that fails the test if there are any extras?
	Extras []Result
}

// Passed returns true if there were no mismatches or missing results.
func (c *Comparison) Passed() bool {
	return len(c.Mismatches) == 0 && len(c.Misses) == 0
}

// Match is a result that matched expectations.
type Match struct {
	TrackingID string
	ProductID  string
	Status     fixtures.VulnerabilityStatus
}

// Mismatch is a result with a status different from expected.
type Mismatch struct {
	TrackingID string
	ProductID  string
	Expected   fixtures.VulnerabilityStatus
	Actual     fixtures.VulnerabilityStatus
}

// Run loads fixtures from the given OCI references and runs them against the auditor.
// Each fixture is run as a subtest named after its reference.
// It calls t.Error for any mismatches or missing results.
func Run(ctx context.Context, t *testing.T, a Auditor, refs []string, opts ...LoaderOption) {
	t.Helper()
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			runOne(ctx, t, a, ref, opts...)
		})
	}
}

func runOne(ctx context.Context, t *testing.T, a Auditor, ref string, opts ...LoaderOption) {
	t.Helper()

	fix, err := LoadFixture(ctx, ref, opts...)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	t.Logf("loaded fixture %s (manifest: %s)", ref, fix.Manifest)
	t.Logf("%d VEX documents, %d expected results", len(fix.VEXDocuments), len(fix.Expected))

	csafReaders := func(yield func(io.Reader) bool) {
		for _, doc := range fix.VEXDocuments {
			if !yield(bytes.NewReader(doc)) {
				return
			}
		}
	}
	results, err := a.Audit(ctx, t, fix.Reference, csafReaders)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Logf("auditor returned %d results", len(results))

	cmp := Compare(fix.Expected, results)
	cmp.Fixture = ref

	for _, m := range cmp.Mismatches {
		t.Errorf("MISMATCH %s/%s: got %s, want %s",
			m.TrackingID, m.ProductID, m.Actual, m.Expected)
	}
	for _, m := range cmp.Misses {
		t.Errorf("MISSING %s/%s: expected %s", m.ID, m.Product, m.Status)
	}

	if len(cmp.Extras) > 0 {
		t.Logf("note: scanner reported %d results not in fixture", len(cmp.Extras))
		for _, e := range cmp.Extras {
			t.Logf("EXTRA %s/%s: %s (package: %s)", e.TrackingID, e.ProductID, e.Status, e.Package)
		}
	}
	if len(cmp.Matches) > 0 {
		t.Logf("matched %d expected results", len(cmp.Matches))
	}
}
