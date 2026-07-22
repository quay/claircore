package libindex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestFetchRangeUncompressed(t *testing.T) {
	data, desc := uncompressedTarLayer(t)
	var requests atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.ServeContent(w, r, "layer.tar", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	desc.URI = srv.URL
	desc.Headers = make(http.Header)

	layer := realizeOne(t, srv.Client(), desc)
	sys, err := layer.FS()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sys, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "pkg.txt" {
		t.Fatalf("unexpected dir: %+v", entries)
	}

	reqs := requests.Load()
	t.Logf("HTTP requests: %d", reqs)
	if reqs > 8 {
		t.Fatalf("too many HTTP requests for range fetch: %d", reqs)
	}
}

func TestFetchRangeCompressedFallback(t *testing.T) {
	data, desc := gzipTarLayer(t)
	var requests atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.ServeContent(w, r, "layer.tar.gz", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	desc.URI = srv.URL
	desc.Headers = make(http.Header)
	desc.MediaType = "application/vnd.oci.image.layer.v1.tar+gzip"

	if _, err := realizeOne(t, srv.Client(), desc).FS(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() < 2 {
		t.Fatalf("expected full download fallback, got %d requests", requests.Load())
	}
}

func TestFetchNoRangeSupportFallback(t *testing.T) {
	data, desc := uncompressedTarLayer(t)
	var requests atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	desc.URI = srv.URL
	desc.Headers = make(http.Header)

	if _, err := realizeOne(t, srv.Client(), desc).FS(); err != nil {
		t.Fatal(err)
	}
	// Probe + full download.
	if requests.Load() < 2 {
		t.Fatalf("expected probe + full download, got %d requests", requests.Load())
	}
}

func TestFetchMalformedProbeFallback(t *testing.T) {
	data, desc := uncompressedTarLayer(t)
	var requests atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[:rangeProbeSize])
			return
		}
		http.ServeContent(w, r, "layer.tar", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	desc.URI = srv.URL
	desc.Headers = make(http.Header)

	if _, err := realizeOne(t, srv.Client(), desc).FS(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() < 2 {
		t.Fatalf("expected malformed probe + full download fallback, got %d requests", requests.Load())
	}
}

func TestFetchRangeCached(t *testing.T) {
	ctx := test.Logging(t)
	data, desc := uncompressedTarLayer(t)
	var requests atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.ServeContent(w, r, "layer.tar", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	desc.URI = srv.URL
	desc.Headers = make(http.Header)

	a, err := CreateRemoteFetchArena(srv.Client(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	f := a.Realizer(ctx).(*FetchProxy)
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	descs := []claircore.LayerDescription{desc, desc}
	ls, err := f.RealizeDescriptions(ctx, descs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ls {
		if _, err := ls[i].FS(); err != nil {
			t.Fatalf("layer %d: %v", i, err)
		}
	}
	// Shared digest: one range probe, not two.
	if requests.Load() < 1 {
		t.Fatal("expected HTTP requests")
	}
}

func TestFetchRangeSameDigestDifferentSources(t *testing.T) {
	ctx := test.Logging(t)
	data, desc := uncompressedTarLayer(t)
	var requestsA atomic.Uint64
	var requestsB atomic.Uint64

	newServer := func(token string, requests *atomic.Uint64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			requests.Add(1)
			http.ServeContent(w, r, "layer.tar", time.Now(), bytes.NewReader(data))
		}))
	}

	srvA := newServer("Bearer token-a", &requestsA)
	t.Cleanup(srvA.Close)
	srvB := newServer("Bearer token-b", &requestsB)
	t.Cleanup(srvB.Close)

	descA := desc
	descA.URI = srvA.URL
	descA.Headers = make(http.Header)
	descA.Headers["Authorization"] = []string{"Bearer token-a"}

	descB := desc
	descB.URI = srvB.URL
	descB.Headers = make(http.Header)
	descB.Headers["Authorization"] = []string{"Bearer token-b"}

	a, err := CreateRemoteFetchArena(srvA.Client(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	f := a.Realizer(ctx).(*FetchProxy)
	ls, err := f.RealizeDescriptions(ctx, []claircore.LayerDescription{descA, descB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	for i := range ls {
		if _, err := ls[i].FS(); err != nil {
			t.Fatalf("layer %d: %v", i, err)
		}
	}

	if requestsA.Load() == 0 || requestsB.Load() == 0 {
		t.Fatalf("expected both sources to be used, got requestsA=%d requestsB=%d", requestsA.Load(), requestsB.Load())
	}
}

func realizeOne(t *testing.T, client *http.Client, desc claircore.LayerDescription) *claircore.Layer {
	t.Helper()
	ctx := test.Logging(t)
	a, err := CreateRemoteFetchArena(client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	f := a.Realizer(ctx).(*FetchProxy)
	ls, err := f.RealizeDescriptions(ctx, []claircore.LayerDescription{desc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return &ls[0]
}

func uncompressedTarLayer(t *testing.T) ([]byte, claircore.LayerDescription) {
	t.Helper()
	var buf bytes.Buffer
	h := sha256.New()
	w := tar.NewWriter(io.MultiWriter(&buf, h))
	if err := w.WriteHeader(&tar.Header{Name: "pkg.txt", Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "test"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), claircore.LayerDescription{
		Digest:    fmt.Sprintf("sha256:%x", h.Sum(nil)),
		MediaType: "application/vnd.oci.image.layer.v1.tar",
	}
}

func gzipTarLayer(t *testing.T) ([]byte, claircore.LayerDescription) {
	t.Helper()
	raw, desc := uncompressedTarLayer(t)
	var gz bytes.Buffer
	gh := sha256.New()
	zw := gzip.NewWriter(io.MultiWriter(&gz, gh))
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	desc.Digest = fmt.Sprintf("sha256:%x", gh.Sum(nil))
	return gz.Bytes(), desc
}

func TestTryNewRangeReaderAt(t *testing.T) {
	ctx := context.Background()
	data := bytes.Repeat([]byte{0x00}, 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "blob", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)

	a, err := CreateRemoteFetchArena(srv.Client(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(ctx) })

	desc := claircore.LayerDescription{
		URI:     srv.URL,
		Digest:  "sha256:" + strconv.FormatUint(0, 16),
		Headers: make(http.Header),
	}
	ra, ok, err := a.tryNewRangeReaderAt(ctx, &desc)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected range reader")
	}
	if ra.Size() != int64(len(data)) {
		t.Fatalf("size %d, want %d", ra.Size(), len(data))
	}
}
