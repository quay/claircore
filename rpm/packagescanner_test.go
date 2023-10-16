package rpm

import (
	"context"
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
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, a))
	}
}

type PackageTestcase struct {
	Name         string
	ManifestFile string
	Ref          test.LayerRef
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
			defer func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			}()
			var l claircore.Layer
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			got, err := s.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			t.Logf("found %d packages", len(got))
		})
	}
}
