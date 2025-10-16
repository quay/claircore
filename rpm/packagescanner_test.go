package rpm

import (
	"context"
	"os"
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
// The nodejs images are currently broken:
////go:generate fetch -o testdata/package/ubi8_nodejs.txtar ubi8/nodejs-*
////go:generate fetch -o testdata/package/ubi9_nodejs.txtar ubi9/nodejs-20

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

						// This is the top-most layer.
						digest := img.ParsedData.Layers[len(img.ParsedData.Layers)-1]
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

						got, err := new(Scanner).Scan(ctx, &ls[0])
						if err != nil {
							t.Error(err)
						}
						seq := rpmtest.PackagesFromManifest(t, slices.Values(m.RPMs))
						want := wart.CollectPointer(seq)

						opts := rpmtest.Options(t, nil)
						if !cmp.Equal(got, want, opts) {
							t.Error(cmp.Diff(got, want, opts))
						}
					})
				}
			})
		}
	}
}

func TestDanglingSymlink(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	desc := claircore.LayerDescription{
		Digest:    test.RandomSHA256Digest(t).String(),
		URI:       "file:///dev/null",
		MediaType: test.MediaType,
		Headers:   make(map[string][]string),
	}

	f, err := os.Open(`testdata/dangling_symlink`)
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

	s := &Scanner{}
	_, err = s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
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

func TestLayerDoesNotExist(t *testing.T) {
	ctx := zlog.Test(t.Context(), t)

	desc := &claircore.LayerDescription{
		Digest:    test.RandomSHA256Digest(t).String(),
		URI:       "file://doesnotexist",
		MediaType: "application/vnd.claircore.filesystem",
	}

	l := &claircore.Layer{}
	err := l.Init(ctx, desc, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	var s Scanner
	_, err = s.Scan(ctx, l)
	if err == nil {
		t.Error("expected an error")
	}
}
