package rpm

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/rpmtest"
)

func TestScan(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	// BUG(hank) This is a dirty hack -- the next person through here should
	// clean this up such that we can systematically test for this information.
	//
	// The main issue is that the repository information is only partially
	// recorded in a separate database.
	nodeRepoIDs := map[string]struct{}{
		"RHEL-9.2.0-updates-20230615.3-AppStream": {},
		"RHEL-9.2.0-updates-20230615.3-BaseOS":    {},
		"rhel-9-for-x86_64-appstream-rpms":        {},
		"rhel-9-for-x86_64-baseos-rpms":           {},
	}
	nodeRepoCheck := func(t testing.TB, pkg *claircore.Package) {
		v, err := url.ParseQuery(pkg.RepositoryHint)
		pkg.RepositoryHint = url.Values{"key": {"199e2f91fd431d51"}}.Encode()
		if err != nil {
			t.Errorf("unable to parse repo hint for %q: %v", pkg.Name, err)
			return
		}

		cmpKey := func(key string, want string) {
			got := v.Get(key)
			if got != want {
				t.Errorf("%s: %s: %s", pkg.Name, key, cmp.Diff(got, want))
			}
		}

		if !v.Has("hash") {
			t.Errorf("%s: missing key %q", pkg.Name, "hash")
		}
		cmpKey("key", "199e2f91fd431d51")

		if v.Has("reposrc") {
			cmpKey("reposrc", "dnf")
			id := v.Get("repoid")
			if _, ok := nodeRepoIDs[id]; !ok {
				t.Errorf("%s: unknown repo ID %q", pkg.Name, id)
			}
		}
	}

	tt := []PackageTestcase{
		{
			Name:         "BDB",
			ManifestFile: "bdb.rpm-manifest.json",
			// Some forgotten CentOS layer.
			Ref: test.LayerRef{
				Registry: "docker.io",
				Name:     "library/centos",
				Digest:   `sha256:729ec3a6ada3a6d26faca9b4779a037231f1762f759ef34c08bdd61bf52cd704`,
			},
		},
		{
			Name:         "SQLite",
			ManifestFile: "sqlite.rpm-manifest.json",
			// Layer from registry.access.redhat.com/ubi9/ubi@sha256:f14f9eb6c5ec6ea9664b54ea8816462e11abc096954d59eac536b64873d908f2
			Ref: test.LayerRef{
				Registry: "registry.access.redhat.com",
				Name:     "ubi9/ubi",
				Digest:   `sha256:6505b024e539929a1909c8820535221fe70806ce5467b5f30aef8d45a4a97da7`,
			},
		},
		{
			Name:         "NodeJS",
			ManifestFile: "nodejs.rpm-manifest.json",
			// Layer from registry.access.redhat.com/ubi9/nodejs-18@sha256:1ff5080686736cbab820ec560873c59bd80659a2b2f8d8f4e379301a910e5d54
			Ref: test.LayerRef{
				Registry: "registry.access.redhat.com",
				Name:     "ubi9/nodejs-18",
				Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
			},
			Repo: nodeRepoCheck,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, a))
	}
}

type PackageTestcase struct {
	// This hook is needed because the pyxis "rpm manifest" does not contain
	// this information.
	Repo         func(testing.TB, *claircore.Package)
	Ref          test.LayerRef
	Name         string
	ManifestFile string
}

func (tc PackageTestcase) Run(ctx context.Context, a *test.CachedArena) func(*testing.T) {
	s := &Scanner{}
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(ctx, t)
		a.LoadLayerFromRegistry(ctx, t, tc.Ref)
		wf, err := os.Open(filepath.Join("testdata/", tc.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := wf.Close(); err != nil {
				t.Error(err)
			}
		})
		want := rpmtest.PackagesFromRPMManifest(t, wf)
		r := a.Realizer(ctx).(*test.CachedRealizer)
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		ls, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
			{
				Digest:    tc.Ref.Digest,
				URI:       "http://example.com",
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		got, err := s.Scan(ctx, &ls[0])
		if err != nil {
			t.Error(err)
		}
		if tc.Repo != nil {
			for _, p := range got {
				tc.Repo(t, p)
			}
		}
		t.Logf("found %d packages", len(got))
		if !cmp.Equal(got, want, rpmtest.Options) {
			t.Error(cmp.Diff(got, want, rpmtest.Options))
		}
	}
}

func TestLayer(t *testing.T) {
	ctx := context.Background()
	ents, err := os.ReadDir(`testdata/layers`)
	if err != nil {
		t.Fatal(err)
	}
	var s Scanner
	desc := claircore.LayerDescription{
		Digest:    test.RandomSHA256Digest(t).String(),
		URI:       "file:///dev/null",
		MediaType: test.MediaType,
		Headers:   make(map[string][]string),
	}

	for _, e := range ents {
		n := e.Name()
		if n == ".gitignore" || n == "README.md" {
			continue
		}
		t.Run(n, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(filepath.Join(`testdata/layers`, n))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			})
			var l claircore.Layer
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})

			got, err := s.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			t.Logf("found %d packages", len(got))
		})
	}
}
