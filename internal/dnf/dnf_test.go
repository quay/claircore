package dnf

import (
	"context"
	"io/fs"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

type testCase struct {
	Name    string
	FS      fs.FS
	Package claircore.Package
	Want    string
}

func (tc *testCase) Run(ctx context.Context, t *testing.T) {
	t.Run(tc.Name, func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		seq := func(yield func(claircore.Package, error) bool) {
			yield(tc.Package, nil)
		}
		wrapped, err := Wrap(ctx, tc.FS, seq)
		if err != nil {
			t.Errorf("error creating wrapper: %v", err)
		}

		for p := range wrapped {
			if got, want := p.RepositoryHint, tc.Want; got != want {
				t.Errorf("incorrect repository hint: got: %q, want: %q", p.RepositoryHint, tc.Want)
			}
		}
	})
}

func TestWrap(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sys := os.DirFS("testdata")

	tcs := []testCase{
		{
			Name: "Found",
			FS:   sys,
			Package: claircore.Package{
				Name:           "apr-util-bdb",
				Version:        "1.6.1-23.el9",
				Kind:           claircore.BINARY,
				Arch:           "x86_64",
				RepositoryHint: "something=nothing",
			},
			Want: "repoid=rhel-9-for-x86_64-appstream-rpms&something=nothing",
		},
		{
			Name: "Absent",
			FS:   sys,
			Package: claircore.Package{
				Name:           "apr-util-bdb",
				Version:        "1.7.1-23.el9", // different version
				Kind:           claircore.BINARY,
				Arch:           "x86_64",
				RepositoryHint: "something=nothing",
			},
			Want: "something=nothing",
		},
	}
	for _, tc := range tcs {
		tc.Run(ctx, t)
	}
}

func TestFindRepoids(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sys := os.DirFS("testdata")

	got, err := FindRepoids(ctx, sys)
	if err != nil {
		t.Errorf("error finding repoids: %v", err)
	}
	slices.Sort(got)
	got = slices.Compact(got)
	want := []string{"rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
