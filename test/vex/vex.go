package vex

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/tools/txtar"
)

var tracer trace.Tracer

func init() {
	tracer = otel.Tracer("github.com/quay/claircore/test/vex")
}

func parseFilenameHeaders(data []byte) (string, http.Header, error) {
	pf, h, _ := bytes.Cut(data, []byte{' '})
	compressedFilepath := bytes.TrimSuffix(pf, []byte{'\n'})
	h = bytes.ReplaceAll(h, []byte(`\n`), []byte{'\n'})
	// Do headers
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(h)))
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return "", nil, err
	}
	return string(compressedFilepath), http.Header(hdr), nil
}

func ServeSecDB(ctx context.Context, t *testing.T, txtarFile string) (string, *http.Client) {
	ctx, span := tracer.Start(ctx, "ServeSecDB")
	defer span.End()

	mux := http.NewServeMux()
	archive, err := txtar.ParseFile(txtarFile)
	if err != nil {
		t.Fatal(err)
	}
	relFilepath, headers, err := parseFilenameHeaders(archive.Comment)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Base(relFilepath)
	mux.HandleFunc("/"+filename, func(w http.ResponseWriter, r *http.Request) {
		_, span := tracer.Start(ctx, r.URL.Path,
			trace.WithLinks(trace.LinkFromContext(ctx)),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		for k, v := range headers {
			w.Header().Set(k, v[0])
		}

		switch r.Method {
		case http.MethodHead:
		case http.MethodGet:
			f, err := os.Open("testdata/" + relFilepath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(w, f); err != nil {
				t.Fatal(err)
			}
		}
	})
	for _, f := range archive.Files {
		urlPath, headers, err := parseFilenameHeaders([]byte(f.Name))
		if err != nil {
			t.Fatal(err)
		}
		fi := f
		mux.HandleFunc(urlPath, func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range headers {
				w.Header().Set(k, v[0])
			}
			_, err := w.Write(bytes.TrimSuffix(fi.Data, []byte{'\n'}))
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}
