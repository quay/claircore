package test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/fetch"
)

// AnyDescription is pre-made [LayerDescription] for cases where the actual
// contents of the description *shouldn't* matter.
var AnyDescription = claircore.LayerDescription{
	Digest:    `sha256:` + strings.Repeat(`deadbeef`, 8),
	URI:       `example:test.AnyDescription`,
	MediaType: MediaType,
	Headers:   make(map[string][]string),
}

type layerserver struct {
	now   time.Time
	blobs []*bytes.Reader
}

func (l *layerserver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ns := path.Base(r.URL.Path)
	n, err := strconv.Atoi(ns)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if n < 0 || n >= len(l.blobs) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("content-type", "application/vnd.oci.image.layer.v1.tar")
	http.ServeContent(w, r, "layer.tar", l.now, l.blobs[n])
}

// ServeLayers constructs "n" random layers, arranges to serve them, and returns
// corresponding LayerDescriptions.
func ServeLayers(t *testing.T, n int) (*http.Client, []claircore.LayerDescription) {
	const filesize = 32
	lsrv := &layerserver{
		now:   time.Now(),
		blobs: make([]*bytes.Reader, n),
	}
	descs := make([]claircore.LayerDescription, n)
	srv := httptest.NewServer(lsrv)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	for i := range n {
		buf := &bytes.Buffer{}
		h := sha256.New()
		w := tar.NewWriter(io.MultiWriter(buf, h))
		u, err := u.Parse(strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}

		if err := w.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     "./randomfile",
			Size:     filesize,
			Mode:     0755,
			Uid:      1000,
			Gid:      1000,
			ModTime:  lsrv.now,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, io.LimitReader(rand.Reader, filesize)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		lsrv.blobs[i] = bytes.NewReader(buf.Bytes())
		d := &descs[i]
		d.MediaType = "application/vnd.oci.image.layer.v1.tar"
		d.Headers = make(http.Header)
		d.URI = u.String()
		d.Digest = fmt.Sprintf("sha256:%x", h.Sum(nil))
	}

	return srv.Client(), descs
}

// RealizeLayers uses fetch.Layer to populate a directory and returns a slice of Layers describing them.
//
// Any needed cleanup is handled via the passed [testing.T].
func RealizeLayers(ctx context.Context, t *testing.T, refs ...LayerRef) []claircore.Layer {
	ret := make([]claircore.Layer, len(refs))
	fetchCh := make(chan int)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range fetchCh {
				id, err := claircore.ParseDigest(refs[n].Digest)
				if err != nil {
					t.Error(err)
					continue
				}
				f, err := fetch.Layer(ctx, t, refs[n].Registry, refs[n].Name, id)
				if err != nil {
					t.Error(err)
					continue
				}
				t.Cleanup(func() {
					if err := f.Close(); err != nil {
						t.Errorf("closing %q: %v", f.Name(), err)
					}
				})
				desc := claircore.LayerDescription{
					URI:    "file:///dev/null",
					Digest: id.String(),
					// Bit of bad coupling seeping in here: all tar-based layers
					// are handled the same, so this doesn't matter as long as
					// it's a tar.
					MediaType: MediaType,
				}
				if err := ret[n].Init(ctx, &desc, f); err != nil {
					t.Error(err)
				}
				t.Cleanup(func() {
					l := &ret[n]
					if err := l.Close(); err != nil {
						t.Errorf("closing %q: %v", l.Hash, err)
					}
				})
			}
		}()
	}
	for n := range refs {
		fetchCh <- n
	}
	close(fetchCh)
	wg.Wait()
	return ret
}

// RealizeLayer is a helper around [RealizeLayers] for a single layer.
//
// This is useful for testing a Scanner implementation.
func RealizeLayer(ctx context.Context, t *testing.T, ref LayerRef) *claircore.Layer {
	t.Helper()
	ls := RealizeLayers(ctx, t, ref)
	return &ls[0]
}
