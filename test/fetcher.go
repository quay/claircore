package test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/claircore/test/integration"
)

// MediaType is a media type that can be used in [claircore.LayerDescription]s
// in tests.
const MediaType = `application/vnd.oci.image.layer.nondistributable.v1.tar`

// CachedArena is an [indexer.FetchArena] that populates Layers out of
// the testing caches.
type CachedArena struct {
	remote string
	local  string
}

var _ indexer.FetchArena = (*CachedArena)(nil)

// NewCachedArena returns an initialized CachedArena.
func NewCachedArena(t testing.TB) *CachedArena {
	return &CachedArena{
		remote: filepath.Join(integration.CacheDir(t), "layer"),
		local:  integration.PackageCacheDir(t),
	}
}

// LoadLayerFromRegistry fetches a layer from a registry into the appropriate cache.
func (a *CachedArena) LoadLayerFromRegistry(ctx context.Context, t testing.TB, ref LayerRef) {
	t.Helper()
	// Fetched layers are stored in the global cache.
	d, err := claircore.ParseDigest(ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetch.Layer(ctx, t, http.DefaultClient, ref.Registry, ref.Name, d)
	if err != nil {
		t.Fatal(err)
	}
}

// LayerRef is a remote layer.
type LayerRef struct {
	Registry string
	Name     string
	Digest   string
}

// GenerateLayer is used for tests that generate their layer data rather than
// fetch it from a registry.
//
// If the test fails, the cached file is removed. If successful, the layer can
// be referenced by using a relative file URI for "name". That is, if the passed
// name is "layer.tar", a [claircore.LayerDescription] should use a URI of
// "file:layer.tar".
//
// It is the caller's responsibility to ensure that "name" is unique per-package.
func (a *CachedArena) GenerateLayer(t testing.TB, name string, stamp time.Time, gen func(testing.TB, *os.File)) {
	t.Helper()
	GenerateFixture(t, name, stamp, gen)
}

// Realizer implements [indexer.FetchArena].
func (a *CachedArena) Realizer(_ context.Context) indexer.Realizer {
	return &CachedRealizer{
		remote: a.remote,
		local:  a.local,
	}
}

// Close implements [indexer.FetchArena].
func (a *CachedArena) Close(_ context.Context) error {
	return nil
}

// CachedRealizer is the [indexer.Realizer] returned by [CachedArena].
type CachedRealizer struct {
	remote string
	local  string
}

var (
	_ indexer.Realizer            = (*CachedRealizer)(nil)
	_ indexer.DescriptionRealizer = (*CachedRealizer)(nil)
)

// RealizeDescriptions implements [indexer.DescriptionRealizer].
func (r *CachedRealizer) RealizeDescriptions(ctx context.Context, descs []claircore.LayerDescription) ([]claircore.Layer, error) {
	out := make([]claircore.Layer, len(descs))
	var success bool
	defer func() {
		if success {
			return
		}
		for i := range out {
			if out[i].URI != "" {
				out[i].Close()
			}
		}
	}()

	for i := range descs {
		d := &descs[i]
		var n string

		u, err := url.Parse(d.URI)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "http", "https":
			// Ignore the URI.
			k, h, ok := strings.Cut(d.Digest, ":")
			if !ok {
				panic("invalid digest")
			}
			n = filepath.Join(r.remote, k, h)
		case "file":
			if u.Opaque == "" {
				return nil, fmt.Errorf("bad URI: %v", u)
			}
			n = filepath.Join(r.local, u.Opaque)
		default:
			return nil, fmt.Errorf("unknown scheme: %q", u.Scheme)
		}

		f, err := os.Open(n)
		if err != nil {
			return nil, fmt.Errorf("unable to open %q: %v", n, err)
		}
		if err := out[i].Init(ctx, d, f); err != nil {
			return nil, err
		}
	}

	success = true
	return out, nil
}

// Realize implements [indexer.Realizer].
func (r *CachedRealizer) Realize(ctx context.Context, ls []*claircore.Layer) error {
	ds := wart.LayersToDescriptions(ls)
	ret, err := r.RealizeDescriptions(ctx, ds)
	if err != nil {
		return err
	}
	wart.CopyLayerPointers(ls, ret)
	return nil
}

// Close implements [indexer.Realizer] and [indexer.DescriptionRealizer].
func (r *CachedRealizer) Close() error {
	return nil
}
