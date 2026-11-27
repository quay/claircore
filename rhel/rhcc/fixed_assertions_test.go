package rhcc

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestFixedBuildAssessment(t *testing.T) {
	for name, tc := range map[string]struct {
		version, fixed, cpe string
		want                bool
	}{
		"older":                   {"1775604308", "1775604309", "4.19", false},
		"at fix":                  {"1775604309", "1775604309", "4.19", true},
		"newer":                   {"1793816697", "1775604309", "4.19", true},
		"other product":           {"1793816697", "1775604309", "4.20", false},
		"not affected":            {"1775604308", "", "4.19", true},
		"unknown product context": {"1793816697", "1775604309", "gold", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := &claircore.IndexRecord{
				Package: &claircore.Package{Kind: types.AncestryPackage, Version: tc.version},
			}
			if tc.cpe == "gold" {
				r.Repository = &GoldRepo
			} else {
				r.Repository = cpeRepo("cpe:/a:redhat:openshift:" + tc.cpe + "::el9")
			}
			v := &claircore.Vulnerability{
				Package: &claircore.Package{Kind: types.AncestryPackage},
				Repo:    cpeRepo("cpe:/a:redhat:openshift:4.19::el9"),
				Invert:  true, FixedInVersion: tc.fixed,
			}
			got, err := Matcher.Vulnerable(test.Logging(t), r, v)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
