package rhel

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/rpmtest"
)

//go:generate -command fetch go run github.com/quay/claircore/test/cmd/fetch-container-rpm-manifest
//go:generate fetch -o testdata/package/ubi8_ubi.txtar ubi8/ubi
//go:generate fetch -o testdata/package/ubi9_ubi.txtar ubi9/ubi
//go:generate fetch -o testdata/package/ubi9_httpd-24.txtar ubi9/httpd-24

func TestPackageDetection(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ms, err := filepath.Glob("testdata/package/*.txtar")
	if err != nil {
		panic("programmer error") // static glob
	}

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	// BUG(hank) The repoid information seems to not currently exist in Pyxis.
	// The tests here use a hard-coded allowlist.
	repoAllow := map[string][]string{
		"registry.access.redhat.com/ubi9/httpd-24": {"RHEL-9.0.0-updates-20220503.2-AppStream", "RHEL-9.0.0-updates-20220503.2-BaseOS"},
	}

	for _, m := range ms {
		ar, err := rpmtest.OpenArchive(ctx, m)
		if err != nil {
			t.Error(err)
			continue
		}

		for _, ref := range ar.Repositories() {
			t.Run(ref, func(t *testing.T) {
				t.Parallel()

				arches := map[string]struct{}{}
				reg, repo, _ := strings.Cut(ref, "/")
				imgs, err := ar.Image(reg, repo)
				if err != nil {
					t.Fatal(err)
				}

				for _, img := range imgs.Data {
					// Only consider the first listed instance of an
					// architecture, since that's the only rpm manifest that
					// will be populated.
					if _, skip := arches[img.Archtecture]; skip {
						continue
					}
					arches[img.Archtecture] = struct{}{}

					t.Run(img.Archtecture, func(t *testing.T) {
						ctx := zlog.Test(ctx, t)
						m, err := ar.Manifest(img.ID)
						if err != nil {
							t.Fatal(err)
						}

						repos := repoAllow[ref]
						for _, r := range img.ParsedData.Repos {
							repos = append(repos, r.ID)
						}
						t.Logf("allowlisting rpm repositories: %#v", repos)

						var got []*claircore.Package
						// Start with the top-most layer.
						for i, digest := range img.ParsedData.Layers {
							layerRef := test.LayerRef{
								Registry: reg,
								Name:     repo,
								Digest:   digest,
							}

							// Fetch the layer via the test caching machinery.
							a.LoadLayerFromRegistry(ctx, t, layerRef)
							r := a.Realizer(ctx).(*test.CachedRealizer)
							t.Cleanup(func() {
								if err := r.Close(); err != nil {
									t.Error(err)
								}
							})
							ls, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
								{
									Digest:    digest,
									URI:       "http://example.com",
									MediaType: test.MediaType,
									Headers:   make(map[string][]string),
								},
							})
							if err != nil {
								t.Fatal(err)
							}

							got, err = new(PackageScanner).Scan(ctx, &ls[0])
							if err != nil {
								t.Error(err)
							}
							if len(got) != 0 {
								break
							}
							t.Logf("skipped layer %d (%s): no packages", i+1, digest)
						}

						seq := rpmtest.PackagesFromManifest(t, slices.Values(m.RPMs))
						want := wart.CollectPointer(seq)

						opts := rpmtest.Options(t, repos)
						if !cmp.Equal(got, want, opts) {
							t.Error(cmp.Diff(got, want, opts))
						}
					})
				}
			})
		}
	}
}
