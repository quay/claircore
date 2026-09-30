package matcher

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

type stubMatcher struct{}

func (stubMatcher) Name() string                       { return "stub" }
func (stubMatcher) Filter(*claircore.IndexRecord) bool { return true }
func (stubMatcher) Query() []driver.MatchConstraint    { return nil }
func (stubMatcher) Vulnerable(context.Context, *claircore.IndexRecord, *claircore.Vulnerability) (bool, error) {
	return true, nil
}

type countingMatcher struct {
	stubMatcher
	n int
}

func (m *countingMatcher) Vulnerable(ctx context.Context, rec *claircore.IndexRecord, v *claircore.Vulnerability) (bool, error) {
	m.n++
	return stubMatcher{}.Vulnerable(ctx, rec, v)
}

type authMatcher struct{ *countingMatcher }

func (*authMatcher) VersionFilter()             {}
func (*authMatcher) VersionAuthoritative() bool { return true }

type stubStore struct {
	vulns map[string][]*claircore.Vulnerability
}

func (s stubStore) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	if opts.Vulnerable == nil {
		return s.vulns, nil
	}
	out := make(map[string][]*claircore.Vulnerability)
	seen := make(map[string]map[string]struct{})
	for _, record := range records {
		id := record.Package.ID
		for _, vuln := range s.vulns[id] {
			ok, err := opts.Vulnerable(ctx, record, vuln)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if seen[id] == nil {
				seen[id] = make(map[string]struct{})
			}
			if _, dup := seen[id][vuln.ID]; dup {
				continue
			}
			seen[id][vuln.ID] = struct{}{}
			out[id] = append(out[id], vuln)
		}
	}
	return out, nil
}
func (stubStore) GetEnrichment(context.Context, string, []string) ([]driver.EnrichmentRecord, error) {
	return nil, nil
}

func TestMatchAuthoritativeOmitsVulnerable(t *testing.T) {
	ctx := t.Context()
	pkgID := "test-pkg"
	rec := &claircore.IndexRecord{Package: &claircore.Package{ID: pkgID, Name: "test"}}
	store := stubStore{vulns: map[string][]*claircore.Vulnerability{
		pkgID: {{ID: "CVE-2024-0001"}},
	}}

	t.Run("not authoritative", func(t *testing.T) {
		m := &countingMatcher{}
		if _, err := NewController(m, store).Match(ctx, []*claircore.IndexRecord{rec}); err != nil {
			t.Fatal(err)
		}
		if m.n != 1 {
			t.Fatalf("Vulnerable called %d times, want 1", m.n)
		}
	})
	t.Run("authoritative", func(t *testing.T) {
		m := &countingMatcher{}
		if _, err := NewController(&authMatcher{m}, store).Match(ctx, []*claircore.IndexRecord{rec}); err != nil {
			t.Fatal(err)
		}
		if m.n != 0 {
			t.Fatalf("Vulnerable called %d times, want 0", m.n)
		}
	})
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
