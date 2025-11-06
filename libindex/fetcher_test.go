package libindex

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test"
)

type fetchTestcase struct {
	N int
}

func (tc fetchTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		c, descs := test.ServeLayers(t, tc.N)
		for _, l := range descs {
			t.Logf("%+v", l)
		}
		a := NewRemoteFetchArena(c, t.TempDir())

		fetcher := a.Realizer(ctx)
		layers := wart.DescriptionsToLayers(descs)
		if err := fetcher.Realize(ctx, layers); err != nil {
			t.Error(err)
		}
		for _, l := range layers {
			t.Logf("%+v", l)
		}
		if err := fetcher.Close(); err != nil {
			t.Error(err)
		}
	}
}

func TestFetchSimple(t *testing.T) {
	ctx := context.Background()
	tt := []fetchTestcase{
		{N: 1},
		{N: 4},
		{N: 32},
	}

	for _, tc := range tt {
		t.Run(strconv.Itoa(tc.N), tc.Run(ctx))
	}
}

func TestFetchInvalid(t *testing.T) {
	// TODO(hank) Rewrite this into unified testcases.
	tt := []struct {
		name  string
		layer []*claircore.Layer
	}{
		{
			name: "no remote path or local path provided",
			layer: []*claircore.Layer{
				{
					URI: "",
				},
			},
		},
		{
			name: "path with no scheme",
			layer: []*claircore.Layer{
				{
					URI: "www.example.com/path/to/tar?query=one",
				},
			},
		},
	}

	tmp := t.TempDir()
	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := test.Logging(t)
			a := NewRemoteFetchArena(http.DefaultClient, tmp)
			fetcher := a.Realizer(ctx)
			if err := fetcher.Realize(ctx, table.layer); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestFetchConcurrent(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	descs, h := commonLayerServer(t, 25)
	srv := httptest.NewUnstartedServer(h)
	srv.Start()
	for i := range descs {
		descs[i].URI = srv.URL + descs[i].URI
	}
	t.Cleanup(srv.Close)
	a := NewRemoteFetchArena(srv.Client(), t.TempDir())
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("OldInterface", func(t *testing.T) {
		t.Run("Thread", func(t *testing.T) {
			run := func(a *RemoteFetchArena, ls []claircore.LayerDescription) func(*testing.T) {
				ps := wart.DescriptionsToLayers(ls)
				// Leave the bottom half the same, shuffle the top half.
				off := len(ps) / 2
				rand.Shuffle(off, func(i, j int) {
					i, j = i+off, j+off
					ps[i], ps[j] = ps[j], ps[i]
				})
				return func(t *testing.T) {
					t.Parallel()
					ctx := test.Logging(t)
					f := a.Realizer(ctx)
					t.Cleanup(func() {
						if err := f.Close(); err != nil {
							t.Error(err)
						}
					})
					if err := f.Realize(ctx, ps); err != nil {
						t.Error(err)
					}
				}
			}
			for i := 0; i < runtime.GOMAXPROCS(0); i++ {
				t.Run(strconv.Itoa(i), run(a, descs))
			}
		})
	})

	t.Run("NewInterface", func(t *testing.T) {
		t.Run("Thread", func(t *testing.T) {
			run := func(a *RemoteFetchArena, descs []claircore.LayerDescription) func(*testing.T) {
				ds := make([]claircore.LayerDescription, len(descs))
				copy(ds, descs)
				// Leave the bottom half the same, shuffle the top half.
				off := len(ds) / 2
				rand.Shuffle(off, func(i, j int) {
					i, j = i+off, j+off
					ds[i], ds[j] = ds[j], ds[i]
				})
				return func(t *testing.T) {
					t.Parallel()
					ctx := test.Logging(t)
					f := a.Realizer(ctx).(*FetchProxy)
					defer func() {
						if err := f.Close(); err != nil {
							t.Error(err)
						}
					}()
					ls, err := f.RealizeDescriptions(ctx, ds)
					if err != nil {
						t.Errorf("RealizeDescriptions error: %v", err)
					}
					t.Logf("layers: %v", ls)
				}
			}
			for i := 0; i < runtime.GOMAXPROCS(0); i++ {
				t.Run(strconv.Itoa(i), run(a, descs))
			}
		})
	})
}

func commonLayerServer(t testing.TB, ct int) ([]claircore.LayerDescription, http.Handler) {
	// TODO(hank) Cache all this? The contents are basically static.
	t.Helper()
	dir := t.TempDir()
	descs := make([]claircore.LayerDescription, ct)
	fetch := make(map[string]*uint64, ct)
	for i := range ct {
		n := strconv.Itoa(i)
		f, err := os.Create(filepath.Join(dir, strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		w := tar.NewWriter(io.MultiWriter(f, h))
		if err := w.WriteHeader(&tar.Header{
			Name: n,
			Size: 33,
		}); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "%032d\n", i)

		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		l := &descs[i]
		l.URI = "/" + strconv.Itoa(i)
		fetch[l.URI] = new(uint64)
		l.Digest = fmt.Sprintf("sha256:%x", h.Sum(nil))
		l.Headers = make(http.Header)
		l.MediaType = `application/vnd.oci.image.layer.nondistributable.v1.tar`
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Cleanup(func() {
		// We know we're doing 2 sets of fetches.
		max := ct * 2 * runtime.GOMAXPROCS(0)
		var total int
		for _, v := range fetch {
			total += int(*v)
		}
		switch {
		case total > max:
			t.Errorf("more fetches than should be possible: %d > %d", total, max)
		case total == max:
			t.Errorf("prevented no fetches: %d == %d", total, max)
		case total < max:
			t.Logf("prevented %[3]d fetches: %[1]d < %d", total, max, max-total)
		}
	})
	inner := http.FileServer(http.Dir(dir))
	return descs, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := fetch[r.URL.Path]
		atomic.AddUint64(ct, 1)
		inner.ServeHTTP(w, r)
	})
}
