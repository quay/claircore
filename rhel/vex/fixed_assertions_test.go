package vex

import (
	"os"
	"testing"

	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestFixedContainerAssertions(t *testing.T) {
	// Reduced from the published CVE document. Only the two relevant OCI
	// namespaces were removed; repository URLs and fixed build tags are intact.
	b, err := os.ReadFile("testdata/cve-2025-68121-fixed-containers.json")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := NewParser().Parse(test.Logging(t), b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"openshift4/ose-olm-operator-controller-rhel9": "1775604309",
		"openshift4/ose-olm-catalogd-rhel9":            "1775604244",
	}
	positive, negative := map[string]int{}, map[string]int{}
	for _, v := range vs {
		if v.Repo.Key != rhcc.RepositoryKey {
			continue
		}
		fixed, ok := want[v.Package.Name]
		if !ok || v.FixedInVersion != fixed {
			t.Fatalf("unexpected rule: %+v", v)
		}
		if !v.Invert {
			positive[v.Package.Name]++
			continue
		}
		negative[v.Package.Name]++
		if v.Package.Kind != types.AncestryPackage {
			t.Errorf("fixed assessment kind = %q", v.Package.Kind)
		}
		// The actual database applies this coarse range before the matcher.
		// It must include current image timestamps as well as the fixed build.
		for _, s := range []string{fixed, "1793818345"} {
			p, err := rhctag.Parse(s)
			if err != nil {
				t.Fatal(err)
			}
			n := p.Version(true)
			if v.Range == nil || v.Range.Lower.Compare(&n) > 0 || v.Range.Upper.Compare(&n) < 0 {
				t.Errorf("fixed rule excludes timestamp %s: %+v", s, v.Range)
			}
		}
	}
	for name := range want {
		if positive[name] != 1 || negative[name] != 1 {
			t.Errorf("%s: positive=%d negative=%d; want one of each", name, positive[name], negative[name])
		}
	}
}

func TestFixedAssertionMinorScope(t *testing.T) {
	for name, tc := range map[string]struct {
		fixed string
		in    string
		want  bool
	}{
		"same series": {"v4.19.0-10", "v4.19.2-12", true},
		"next series": {"v4.19.0-10", "v4.20.0-1", false},
		"timestamp":   {"1775604309", "1793816697", true},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := fixedAssertionRange(tc.fixed)
			if err != nil {
				t.Fatal(err)
			}
			v, err := rhctag.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			n := v.Version(true)
			got := r.Lower.Compare(&n) <= 0 && r.Upper.Compare(&n) >= 0
			if got != tc.want {
				t.Errorf("range contains %q = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
