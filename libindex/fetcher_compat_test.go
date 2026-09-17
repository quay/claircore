package libindex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore"
)

func TestFetchFallbackCompatibility(t *testing.T) {
	const contents = "layer contents"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "file", Mode: 0644, Size: int64(len(contents))}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, contents); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		headers     http.Header
		contentType string
		data        []byte
	}{
		"nil request headers":               {contentType: "application/gzip", data: compressed.Bytes()},
		"missing content type compressed":   {headers: make(http.Header), data: compressed.Bytes()},
		"missing content type uncompressed": {headers: make(http.Header), data: archive.Bytes()},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// An empty header suppresses automatic content-type detection.
				w.Header()["Content-Type"] = []string{tc.contentType}
				// Ignore Range to exercise the whole-layer download fallback.
				_, _ = w.Write(tc.data)
			}))
			defer srv.Close()
			a := NewRemoteFetchArena(srv.Client(), t.TempDir())
			defer a.Close(ctx)
			desc := claircore.LayerDescription{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				URI:       srv.URL,
				Digest:    fmt.Sprintf("sha256:%x", sha256.Sum256(tc.data)),
				Headers:   tc.headers,
			}
			var layer claircore.Layer
			var closer io.Closer
			if err := a.fetchInto(ctx, &layer, &closer, &desc)(); err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			layerFS, err := layer.FS()
			if err != nil {
				t.Fatal(err)
			}
			got, err := fs.ReadFile(layerFS, "file")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != contents {
				t.Errorf("got %q, want %q", got, contents)
			}
		})
	}
}
