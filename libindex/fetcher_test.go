package libindex

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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
	runTCs := func(t *testing.T) {
		ctx := t.Context()
		tt := []fetchTestcase{
			{N: 1},
			{N: 4},
			{N: 32},
		}

		for _, tc := range tt {
			t.Run(strconv.Itoa(tc.N), tc.Run(ctx))
		}
	}
	runTCs(t)

	if runtime.GOOS == "linux" {
		t.Run("NoTMPFILE", func(t *testing.T) {
			tryTMPFILE = false
			t.Cleanup(func() { tryTMPFILE = true })
			runTCs(t)
		})
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
	setup := func(t *testing.T, ct int, gz bool) (*RemoteFetchArena, []claircore.LayerDescription) {
		t.Helper()
		stamp := test.Modtime(t, ".")
		name := test.GenerateFixture(t, fmt.Sprintf("layers_%02d_%v.zip", ct, gz), stamp, generateTarballs(ct, gz))
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		})
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		z, err := zip.NewReader(f, fi.Size())
		if err != nil {
			t.Fatal(err)
		}
		desc := make([]claircore.LayerDescription, len(z.File))
		reqCt := make(map[string]*uint64)
		contentType := `application/vnd.oci.image.layer.nondistributable.v1.tar`
		if gz {
			contentType += `+gzip`
		}
		now := time.Now()
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := path.Base(r.URL.EscapedPath())
			ct := reqCt[n]
			atomic.AddUint64(ct, 1)
			w.Header().Set(`content-type`, contentType)
			b, err := fs.ReadFile(z, n)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.ServeContent(w, r, n, now, bytes.NewReader(b))
		})

		srv := httptest.NewUnstartedServer(h)
		srv.EnableHTTP2 = true
		srv.StartTLS()
		for i, zf := range z.File {
			reqCt[zf.Name] = new(uint64)
			d := &desc[i]
			d.URI = srv.URL + "/" + zf.Name
			d.Digest = zf.Comment
			d.Headers = make(http.Header)
			d.MediaType = contentType
		}

		t.Cleanup(srv.Close)
		a := NewRemoteFetchArena(srv.Client(), t.TempDir())
		ctx := test.Logging(t)
		t.Cleanup(func() {
			if err := a.Close(ctx); err != nil {
				t.Error(err)
			}
		})
		return a, desc
	}
	oldInterface := func(a *RemoteFetchArena, ls []claircore.LayerDescription) func(*testing.T) {
		ps := wart.DescriptionsToLayers(ls)
		shuffleSlice(ps)
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
	newInterface := func(a *RemoteFetchArena, descs []claircore.LayerDescription) func(*testing.T) {
		ds := slices.Clone(descs)
		shuffleSlice(ds)
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

	for i := range 2 {
		gz := i == 1
		n := `Uncompressed`
		if gz {
			n = `Compressed`
		}
		t.Run(n, func(t *testing.T) {
			t.Parallel()
			a, descs := setup(t, 25, gz)
			t.Run("OldInterface", func(t *testing.T) {
				for i := 0; i < runtime.GOMAXPROCS(0); i++ {
					t.Run(strconv.Itoa(i), oldInterface(a, descs))
				}
			})

			t.Run("NewInterface", func(t *testing.T) {
				for i := 0; i < runtime.GOMAXPROCS(0); i++ {
					t.Run(strconv.Itoa(i), newInterface(a, descs))
				}
			})
		})
	}
}

// Leave the bottom half the same, shuffle the top half.
func shuffleSlice[S ~[]E, E any](s S) {
	off := len(s) / 2
	rand.Shuffle(off, func(i, j int) {
		i, j = i+off, j+off
		s[i], s[j] = s[j], s[i]
	})
}

func generateTarballs(count int, compressed bool) func(testing.TB, *os.File) {
	return func(t testing.TB, f *os.File) {
		defer f.Close()
		defer f.Sync()
		t.Attr("count", strconv.Itoa(count))
		t.Attr("compressed", strconv.FormatBool(compressed))
		stamp := test.Modtime(t, ".")
		z := zip.NewWriter(f)
		defer z.Close()

		var buf bytes.Buffer
		buf.Grow(2048)
		h := sha256.New()
		for i := range count {
			h.Reset()
			buf.Reset()
			n := fmt.Sprintf("%04d", i)
			w := io.MultiWriter(&buf, h)
			var gz *gzip.Writer
			var tw *tar.Writer
			if compressed {
				gz = gzip.NewWriter(w)
				tw = tar.NewWriter(gz)
			} else {
				tw = tar.NewWriter(w)
			}

			err := tw.WriteHeader(&tar.Header{
				Name: n,
				Size: 33,
			})
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(tw, "%032d\n", i)

			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if gz != nil {
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
			}

			fh := &zip.FileHeader{
				Name:               n,
				Comment:            fmt.Sprintf("sha256:%x", h.Sum(nil)),
				Modified:           stamp,
				UncompressedSize64: uint64(buf.Len()),
			}
			zw, err := z.CreateHeader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(zw, &buf); err != nil {
				t.Fatal(err)
			}
		}
	}
}
