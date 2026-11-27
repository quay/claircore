package matcher

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/libvuln/driver"
	mockstore "github.com/quay/claircore/test/mock/datastore"
	"go.uber.org/mock/gomock"
)

func TestMatchPreservesAssessmentPolarity(t *testing.T) {
	for name, tc := range map[string]struct {
		vulns       []*claircore.Vulnerability
		affected    []string
		notAffected map[string][]string
	}{
		"affected only": {
			vulns:    []*claircore.Vulnerability{{ID: "affected"}},
			affected: []string{"affected"},
		},
		"affected and fixed": {
			vulns:       []*claircore.Vulnerability{{ID: "affected"}, {ID: "fixed", Invert: true}},
			affected:    []string{"affected"},
			notAffected: map[string][]string{"pkg": {"fixed"}},
		},
		"fixed only": {
			vulns:       []*claircore.Vulnerability{{ID: "fixed", Invert: true}},
			notAffected: map[string][]string{"pkg": {"fixed"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mockstore.NewMockVulnerability(ctrl)
			store.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string][]*claircore.Vulnerability{
				"pkg": tc.vulns,
			}, nil)
			ir := &claircore.IndexReport{
				Packages:     map[string]*claircore.Package{"pkg": {ID: "pkg", Name: "stdlib"}},
				Repositories: map[string]*claircore.Repository{"go": {ID: "go", Name: "go", URI: "https://pkg.go.dev/"}},
				Environments: map[string][]*claircore.Environment{"pkg": {{RepositoryIDs: []string{"go"}}}},
			}
			r, err := Match(context.Background(), ir, []driver.Matcher{&gobin.Matcher{}}, store)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.affected, r.PackageVulnerabilities["pkg"]); diff != "" {
				t.Errorf("positive assessments (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.notAffected, r.PackageNotVulnerable); diff != "" {
				t.Errorf("negative assessments (-want +got):\n%s", diff)
			}
		})
	}
}
