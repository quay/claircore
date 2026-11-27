package matcher

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/libvuln/driver"
	mockstore "github.com/quay/claircore/test/mock/datastore"
	"go.uber.org/mock/gomock"
)

func TestMatchPreservesAssessmentPolarity(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mockstore.NewMockVulnerability(ctrl)
	store.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string][]*claircore.Vulnerability{
		"pkg": {{ID: "affected"}, {ID: "fixed", Invert: true}},
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
	if vs := r.PackageVulnerabilities["pkg"]; len(vs) != 1 || vs[0] != "affected" {
		t.Errorf("positive assessments=%v", vs)
	}
	if vs := r.PackageNotVulnerable["pkg"]; len(vs) != 1 || vs[0] != "fixed" {
		t.Errorf("negative assessments=%v", vs)
	}
}
