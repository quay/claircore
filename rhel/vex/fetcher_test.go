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

	"github.com/klauspost/compress/snappy"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/csaf"
)

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

func serveSecDB(t *testing.T, txtarFile string) (string, *http.Client) {
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

func TestFactory(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	root, c := serveSecDB(t, "testdata/server.txt")
	fac := &Factory{}
	err := fac.Configure(ctx, func(v interface{}) error {
		cf := v.(*FactoryConfig)
		cf.URL = root + "/"
		return nil
	}, c)
	if err != nil {
		t.Fatal(err)
	}

	s, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	if len(s.Updaters()) != 1 {
		t.Errorf("expected 1 updater in the updaterset but got %d", len(s.Updaters()))
	}
	data, fp, err := s.Updaters()[0].Fetch(ctx, "")
	if err != nil {
		t.Fatalf("error Fetching, cannot continue: %v", err)
	}
	defer data.Close()
	// Check fingerprint.
	f, err := parseFingerprint(fp)
	if err != nil {
		t.Errorf("fingerprint cannot be parsed: %v", err)
	}
	if f.changesEtag != "something" {
		t.Errorf("bad etag for the changes.csv endpoint: %s", f.changesEtag)
	}
	if f.deletionsEtag != "somethingelse" {
		t.Errorf("bad etag for the deletions.csv endpoint: %s", f.deletionsEtag)
	}

	// Check saved vulns
	expectedLnCt := 7
	lnCt := 0
	r := bufio.NewReader(snappy.NewReader(data))
	for b, err := r.ReadBytes('\n'); err == nil; b, err = r.ReadBytes('\n') {
		_, err := csaf.Parse(bytes.NewReader(b))
		if err != nil {
			t.Error(err)
		}
		lnCt++
	}
	if lnCt != expectedLnCt {
		t.Errorf("got %d entries but expected %d", lnCt, expectedLnCt)
	}

	newData, newFP, err := s.Updaters()[0].Fetch(ctx, driver.Fingerprint(f.String()))
	if err != nil {
		t.Fatalf("error re-Fetching, cannot continue: %v", err)
	}
	defer newData.Close()

	f, err = parseFingerprint(newFP)
	if err != nil {
		t.Errorf("fingerprint cannot be parsed: %v", err)
	}
	if f.changesEtag != "something" {
		t.Errorf("bad etag for the changes.csv endpoint: %s", f.changesEtag)
	}
	if f.deletionsEtag != "somethingelse" {
		t.Errorf("bad etag for the deletions.csv endpoint: %s", f.deletionsEtag)
	}

	r = bufio.NewReader(snappy.NewReader(newData))
	for _, err := r.ReadBytes('\n'); err == nil; _, err = r.ReadBytes('\n') {
		t.Fatal("should not have anymore data")
	}
}
