package test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/fetch"
)

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
// a slice of filled Layer structs.
func ServeLayers(t *testing.T, n int) (*http.Client, []*claircore.Layer) {
	const filesize = 32
	lsrv := &layerserver{
		now:   time.Now(),
		blobs: make([]*bytes.Reader, n),
	}
	ls := make([]*claircore.Layer, n)
	srv := httptest.NewServer(lsrv)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
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
		ls[i] = &claircore.Layer{
			URI: u.String(),
		}
		ls[i].Hash, err = claircore.NewDigest("sha256", h.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
	}

	return srv.Client(), ls
}

type LayerSpec struct {
	Domain, Repo string
	ID           claircore.Digest
}

// RealizeLayers uses fetch.Layer to populate a directory and returns a slice of Layers describing them.
func RealizeLayers(ctx context.Context, t *testing.T, spec ...LayerSpec) []claircore.Layer {
	ret := make([]claircore.Layer, len(spec))
	fetchCh := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range fetchCh {
				id := spec[n].ID
				f, err := fetch.Layer(ctx, t, nil, spec[n].Domain, spec[n].Repo, id)
				if err != nil {
					t.Error(err)
					continue
				}
				ret[n].URI = "file:///dev/null"
				ret[n].Hash = id
				ret[n].SetLocal(f.Name())
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for n := 0; n < len(spec); n++ {
		fetchCh <- n
	}
	close(fetchCh)
	wg.Wait()
	return ret
}
