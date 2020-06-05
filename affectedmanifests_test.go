package claircore_test

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

// TestAffectedManifestsAddAndSort confirms adding to and sorting
// the AffectedManifests struct works correctly.
func TestAffectedManifestsAddAndSort(t *testing.T) {
	vulns := test.GenUniqueVulnerabilities(2, "test-updater")
	manifest := claircore.MustParseDigest(`sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef`)
	affected := claircore.NewAffectedManifests()

	// make vuln 1 higher severity, to test sorting
	vulns[1].NormalizedSeverity = claircore.High

	affected.Add(vulns[0], manifest)
	affected.Add(vulns[1], manifest)

	if len(affected.Vulnerabilities) != 2 {
		t.Fatalf("got: %d, want: %d", len(affected.Vulnerabilities), 2)
	}

	if _, ok := affected.VulnerableManifests[manifest.String()]; !ok {
		t.Fatalf("got: %v, want: %v", ok, true)
	}

	affected.Sort()

	ids := affected.VulnerableManifests[manifest.String()]
	if len(ids) != 2 {
		t.Fatalf("got: %v, want: %v", len(ids), 2)
	}

	v1 := affected.Vulnerabilities[ids[0]]
	v2 := affected.Vulnerabilities[ids[1]]

	if v1.NormalizedSeverity != claircore.High {
		t.Fatalf("got: %v, want: %v", v1.NormalizedSeverity, claircore.High)
	}

	if v2.NormalizedSeverity != claircore.Unknown {
		t.Fatalf("got: %v, want: %v", v1.NormalizedSeverity, claircore.Unknown)
	}
}
