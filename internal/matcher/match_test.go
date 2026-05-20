package matcher

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

type stubMatcher struct{}

func (stubMatcher) Name() string                          { return "stub" }
func (stubMatcher) Filter(*claircore.IndexRecord) bool    { return true }
func (stubMatcher) Query() []driver.MatchConstraint       { return nil }
func (stubMatcher) Vulnerable(context.Context, *claircore.IndexRecord, *claircore.Vulnerability) (bool, error) {
	return true, nil
}

type stubStore struct{ vulns map[string][]*claircore.Vulnerability }

func (s stubStore) Get(context.Context, []*claircore.IndexRecord, datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	return s.vulns, nil
}
func (stubStore) GetEnrichment(context.Context, string, []string) ([]driver.EnrichmentRecord, error) {
	return nil, nil
}

func TestEnrichedMatchInvert(t *testing.T) {
	ctx := t.Context()
	pkgID := "test-pkg"
	ir := &claircore.IndexReport{
		Hash:     claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
		Packages: map[string]*claircore.Package{pkgID: {ID: pkgID, Name: "test"}},
		Environments: map[string][]*claircore.Environment{
			pkgID: {{PackageDB: "test"}},
		},
	}
	store := stubStore{vulns: map[string][]*claircore.Vulnerability{
		pkgID: {{ID: "CVE-2024-0001", Invert: true}},
	}}

	vr, err := EnrichedMatch(ctx, ir, []driver.Matcher{stubMatcher{}}, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vr.PackageNotVulnerable[pkgID]; !ok {
		t.Errorf("expected %q in PackageNotVulnerable", pkgID)
	}
}
