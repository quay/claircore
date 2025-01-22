package rhel

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

func TestPackageScanner(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	a := test.NewCachedArena(t)
	defer func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	}()

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
			Name:         "NodeJS",
			ManifestFile: "nodejs.rpm-manifest.json",
			// Layer from registry.access.redhat.com/ubi9/nodejs-18@sha256:1ff5080686736cbab820ec560873c59bd80659a2b2f8d8f4e379301a910e5d54
			Ref: test.LayerRef{
				Registry: "registry.access.redhat.com",
				Name:     "ubi9/nodejs-18",
				Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
			},
		},
		{
			Name:         "Httpd24NoContentSets",
			ManifestFile: "httpd-24_9.5-1734525854.rpm-manifest.json",
			// Layer from registry.access.redhat.com/ubi9/httpd-24:9.5-1734525854
			Ref: test.LayerRef{
				Registry: "registry.access.redhat.com",
				Name:     "ubi9/httpd-24",
				Digest:   `sha256:572f60f98d5ae116073fa5f8c576fc014afdcd4c68875e37c37032ad2772f653`,
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
	s := &PackageScanner{}
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
		if !cmp.Equal(got, want, rpmtest.Options(t)) {
			t.Error(cmp.Diff(got, want, rpmtest.Options(t)))
		}
	}
}
