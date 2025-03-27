package dnf

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/zlog"
)

type testCase struct {
	name                   string
	pkg                    claircore.Package
	expectedRepositoryHint string
}

var tcs = []testCase{
	{
		name: "found_package",
		pkg: claircore.Package{
			Name:           "apr-util-bdb",
			Version:        "1.6.1-23.el9",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			RepositoryHint: "something=nothing",
		},
		expectedRepositoryHint: "repoid=rhel-9-for-x86_64-appstream-rpms&something=nothing",
	},
	{
		name: "not_found_package",
		pkg: claircore.Package{
			Name:           "apr-util-bdb",
			Version:        "1.7.1-23.el9", //different version
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			RepositoryHint: "something=nothing",
		},
		expectedRepositoryHint: "something=nothing",
	},
}

func TestWrap(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sys := os.DirFS("testdata")
	a, err := NewAnnotator(ctx, sys)
	if err != nil {
		t.Errorf("error creating Annotator: %v", err)
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			seq, errFunc := a.Wrap(ctx, slices.Values([]claircore.Package{tc.pkg}))
			if errFunc() != nil {
				t.Errorf("error wrapping packages: %v", errFunc())
			}
			for p := range seq {
				if p.RepositoryHint != tc.expectedRepositoryHint {
					t.Errorf("incorrect repository hint, wanted %s got %s", p.RepositoryHint, tc.expectedRepositoryHint)
				}
			}
		})
	}
}

func TestFindRepoids(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sys := os.DirFS("testdata")
	repoids, err := FindRepoids(ctx, sys)
	if err != nil {
		t.Errorf("error finding repoids: %v", err)
	}
	slices.Sort(repoids)
	repoids = slices.Compact(repoids)
	expectedRepoIDs := []string{"rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"}
	if !cmp.Equal(repoids, expectedRepoIDs) {
		t.Error(cmp.Diff(repoids, expectedRepoIDs))
	}
}
