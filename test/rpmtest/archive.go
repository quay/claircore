package rpmtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"net/textproto"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/redhat/catalog"
	"github.com/quay/claircore/test/redhat/hydra"
)

// OpenArchive opens the manifest txtar at path "p".
func OpenArchive(_ context.Context, p string) (*Archive, error) {
	ar, err := txtar.ParseFile(p)
	if err != nil {
		return nil, err
	}
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(ar.Comment)))
	h, err := r.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	if g := h.Get("generator"); g != "fetch-container-rpm-manifest" {
		return nil, fmt.Errorf("archive produced by unknown generator: %q", g)
	}

	lookup := make(map[string]*txtar.File, len(ar.Files))
	for i := range ar.Files {
		f := &ar.Files[i]
		lookup[f.Name] = f
	}

	return &Archive{
		ar:     ar,
		h:      h,
		lookup: lookup,
	}, nil
}

const (
	searchResult = `access.redhat.com/hydra/rest/search/kcs`
)

// Archive is a helper for reading the txtar archives as produced by the
// test/cmd/fetch-container-rpm-manifest tool.
type Archive struct {
	ar     *txtar.Archive
	h      textproto.MIMEHeader
	lookup map[string]*txtar.File
}

// URLs reports the URLs that were used while creating the archive.
func (a *Archive) URLs(_ context.Context) []string {
	return a.h.Values("url")
}

// Repositories reports the container image repositories in the archive.
func (a *Archive) Repositories() []string {
	f := a.lookup[searchResult]
	var res hydra.Response
	if err := json.Unmarshal(f.Data, &res); err != nil {
		// The command that built this archive successfully did this unmarshal,
		// so if the current process can't, just panic.
		panic(err)
	}
	out := make([]string, 0, len(res.Response.Docs))
	for _, doc := range res.Response.Docs {
		out = append(out, path.Join(doc.Registry, doc.Repository))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (a *Archive) Image(registry, repo string) (catalog.Images, error) {
	const imagePathFormat = `catalog.redhat.com/api/containers/v1/repositories/registry/%s/repository/%s/images`
	imagePath := fmt.Sprintf(imagePathFormat, registry, repo)
	f, ok := a.lookup[imagePath]
	if !ok {
		return catalog.Images{}, fs.ErrNotExist
	}

	var imgs catalog.Images
	if err := json.Unmarshal(f.Data, &imgs); err != nil {
		return catalog.Images{}, err
	}

	return imgs, nil
}

func (a *Archive) Manifest(id string) (catalog.RpmManifest, error) {
	const manifestPathFormat = `catalog.redhat.com/api/containers/v1/images/id/%s/rpm-manifest`
	manifestPath := fmt.Sprintf(manifestPathFormat, id)
	f, ok := a.lookup[manifestPath]
	if !ok {
		return catalog.RpmManifest{}, fs.ErrNotExist
	}

	var m catalog.RpmManifest
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return catalog.RpmManifest{}, err
	}

	return m, nil
}

// Manifests reports the rpm manifests recorded in the archive.
func (a *Archive) Manifests() iter.Seq2[catalog.RpmManifest, error] {
	return func(yield func(catalog.RpmManifest, error) bool) {
		for _, f := range a.ar.Files {
			if !strings.HasPrefix(f.Name, "catalog.redhat.com") ||
				!strings.HasSuffix(f.Name, "rpm-manifest") {
				continue
			}
			var m catalog.RpmManifest
			err := json.Unmarshal(f.Data, &m)
			if !yield(m, err) {
				return
			}
		}
	}
}

// Images reports the image descriptions recorded in the archive.
func (a *Archive) Images() iter.Seq2[catalog.Image, error] {
	return func(yield func(catalog.Image, error) bool) {
		for _, f := range a.ar.Files {
			if !strings.HasPrefix(f.Name, "catalog.redhat.com") ||
				!strings.HasSuffix(f.Name, "images") {
				continue
			}
			var imgs catalog.Images
			if err := json.Unmarshal(f.Data, &imgs); err != nil {
				if !yield(catalog.Image{}, err) {
					return
				}
				continue
			}
			for _, i := range imgs.Data {
				if !yield(i, nil) {
					return
				}
			}
		}
	}
}

// Repository reports the container image repository recorded in the archive.
func (a *Archive) Repository() (catalog.Repository, error) {
	var r catalog.Repository
	for _, f := range a.ar.Files {
		if !strings.HasPrefix(f.Name, "catalog.redhat.com") ||
			strings.HasSuffix(f.Name, "images") ||
			strings.HasSuffix(f.Name, "rpm-manifest") {
			continue
		}
		return r, json.Unmarshal(f.Data, &r)
	}
	return r, errors.New("no repository object")
}

// Tests runs "tf" on images described in the archive and checks the output with
// the relevant rpm manifest in the archive.
func (a *Archive) Tests(
	ctx context.Context,
	ca *test.CachedArena,
	repoAllow map[string][]string,
	tf func(context.Context, *claircore.Layer) ([]*claircore.Package, error),
) func(*testing.T) {
	if repoAllow == nil {
		repoAllow = make(map[string][]string)
	}
	return func(t *testing.T) {
		for _, ref := range a.Repositories() {
			t.Run(ref, func(t *testing.T) {
				t.Parallel()

				arches := map[string]struct{}{}
				reg, repo, _ := strings.Cut(ref, "/")
				imgs, err := a.Image(reg, repo)
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
						ctx := test.Logging(t)
						m, err := a.Manifest(img.ID)
						if err != nil {
							t.Fatal(err)
						}

						repos := repoAllow[ref]
						for _, r := range img.ParsedData.Repos {
							repos = append(repos, r.ID)
						}
						t.Logf("allowlisting rpm repositories: %#v", repos)

						var got []*claircore.Package
						// Find the top-most layer that returns results.
						for i, digest := range img.ParsedData.Layers {
							layerRef := test.LayerRef{
								Registry: reg,
								Name:     repo,
								Digest:   digest,
							}

							// Fetch the layer via the test caching machinery.
							ca.LoadLayerFromRegistry(ctx, t, layerRef)
							r := ca.Realizer(ctx).(*test.CachedRealizer)
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

							got, err = tf(ctx, &ls[0])
							if err != nil {
								t.Error(err)
							}
							if len(got) != 0 {
								break
							}
							t.Logf("skipped layer %d (%s): no packages", i+1, digest)
						}

						seq := PackagesFromManifest(t, slices.Values(m.RPMs))
						want := wart.CollectPointer(seq)

						opts := Options(t, repos)
						if !cmp.Equal(got, want, opts) {
							t.Error(cmp.Diff(got, want, opts))
						}
					})
				}
			})
		}
	}
}
