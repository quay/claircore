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
	"strconv"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

type fetchTestcase struct {
	N int
}

func (tc fetchTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		c, layers := test.ServeLayers(t, tc.N)
		for _, l := range layers {
			t.Logf("%+v", l)
		}
		a := NewRemoteFetchArena(c, t.TempDir())

		fetcher := a.Realizer(ctx)
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
	ctx := context.Background()
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
			ctx := zlog.Test(ctx, t)
			a := NewRemoteFetchArena(http.DefaultClient, tmp)
			fetcher := a.Realizer(ctx)
			if err := fetcher.Realize(ctx, table.layer); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestFetchConcurrent(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ls, h := commonLayerServer(t, 100)
	srv := httptest.NewUnstartedServer(h)
	srv.Start()
	for i := range ls {
		ls[i].URI = srv.URL + ls[i].URI
	}
	defer srv.Close()
	a := NewRemoteFetchArena(srv.Client(), t.TempDir())

	subtest := func(a *RemoteFetchArena, ls []claircore.Layer) func(*testing.T) {
		// Need to make a copy of all our layers.
		l := make([]claircore.Layer, len(ls))
		copy(l, ls)
		// And then turn into pointers for reasons.
		ps := make([]*claircore.Layer, len(l))
		// Leave the bottom half the same, shuffle the top half.
		rand.Shuffle(len(ps), func(i, j int) {
			ps[i], ps[j] = &l[j], &l[i]
		})
		for i := range ps[:len(ps)/2] {
			ps[i] = &l[i]
		}
		f := a.Realizer(ctx)
		return func(t *testing.T) {
			t.Parallel()
			t.Cleanup(func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx := zlog.Test(ctx, t)
			if err := f.Realize(ctx, ps); err != nil {
				t.Error(err)
			}
		}
	}
	t.Run("group", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			t.Run(strconv.Itoa(i), subtest(a, ls))
		}
	})

	if err := a.Close(ctx); err != nil {
		t.Error(err)
	}
}

func commonLayerServer(t testing.TB, ct int) ([]claircore.Layer, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	ls := make([]claircore.Layer, ct)
	for i := 0; i < ct; i++ {
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
		l := &ls[i]
		l.URI = "/" + strconv.Itoa(i)
		l.Hash, err = claircore.NewDigest("sha256", h.Sum(nil))
		l.Headers = make(http.Header)
		if err != nil {
			t.Fatal(err)
		}
	}
	return ls, http.FileServer(http.Dir(dir))
}
