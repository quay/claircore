package dnf

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

type testCase struct {
	Name    string
	FS      fs.FS
	Package claircore.Package
	Want    string
}

func (tc *testCase) Run(ctx context.Context, t *testing.T) {
	t.Run(tc.Name, func(t *testing.T) {
		ctx := test.Logging(t, ctx)
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
	t.Run("dnf4", func(t *testing.T) {
		ctx := test.Logging(t)
		sys := os.DirFS(filepath.Join("testdata", path.Base(t.Name())))

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
	})
	t.Run("dnf5", func(t *testing.T) {
		ctx := test.Logging(t)
		sys := os.DirFS(filepath.Join("testdata", path.Base(t.Name())))

		tcs := []testCase{
			{
				Name: "Found",
				FS:   sys,
				Package: claircore.Package{
					Name:           "dnf5",
					Version:        "5.2.12.0-1.fc42",
					Kind:           claircore.BINARY,
					Arch:           "x86_64",
					RepositoryHint: "something=nothing",
				},
				Want: "repoid=aea2214b263845539cc9b774ac8dd4c7&something=nothing",
			},
			{
				Name: "Absent",
				FS:   sys,
				Package: claircore.Package{
					Name:           "dnf5",
					Version:        "5.2.12.0-1.fc42.local1", // different version
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
	})
}

func TestFindRepoids(t *testing.T) {
	tcs := []struct {
		Name string
		Want []string
	}{
		{
			Name: "dnf4",
			Want: []string{"rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"},
		},
		{
			Name: "dnf5",
			Want: []string{"aea2214b263845539cc9b774ac8dd4c7"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := test.Logging(t)
			sys := os.DirFS(filepath.Join("testdata", tc.Name))

			got, err := FindRepoids(ctx, sys)
			if err != nil {
				t.Errorf("error finding repoids: %v", err)
			}
			slices.Sort(got)
			want := tc.Want
			slices.Sort(want)

			t.Logf("got: %v, want: %v", got, want)
			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}
