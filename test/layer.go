package test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/quay/claircore"
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
//
// The server goroutines can be cancelled via the passed-in context.
func ServeLayers(ctx context.Context, t *testing.T, n int) []*claircore.Layer {
	const filesize = 32
	lsrv := &layerserver{
		now:   time.Now(),
		blobs: make([]*bytes.Reader, n),
	}
	ls := make([]*claircore.Layer, n)
	srv := httptest.NewServer(lsrv)
	go func() {
		<-ctx.Done()
		srv.CloseClientConnections()
		srv.Close()
	}()
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
			Hash: hex.EncodeToString(h.Sum(nil)),
			URI:  u.String(),
		}
	}

	return ls
}
