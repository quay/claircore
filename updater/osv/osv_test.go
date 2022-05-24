package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(&apiStub{t, ""})
	defer srv.Close()
	ctx := zlog.Test(context.Background(), t)

	u := updater{}
	cfgFunc := func(v interface{}) error {
		cfg := v.(*Config)
		cfg.URL = srv.URL
		return nil
	}
	if err := u.Configure(ctx, cfgFunc, srv.Client()); err != nil {
		t.Error(err)
	}

	rc, fp, err := u.Fetch(ctx, driver.Fingerprint(""))
	if err != nil {
		t.Error(err)
	}
	_ = fp
	if rc != nil {
		rc.Close()
	}
}

type apiStub struct {
	*testing.T
	path string
}

func (a *apiStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Logf("req: %s", r.RequestURI)
	sys := os.DirFS(filepath.Join("testdata", a.path))
	p := r.URL.Path
	switch {
	case p == "/":
		p = "list.xml." + r.URL.Query().Get(`continuation-token`)
		if p == "list.xml." {
			p = "list.xml"
		}
		f, err := sys.Open(p)
		if err != nil {
			a.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, f); err != nil {
			a.Error(err)
		}
	case strings.HasSuffix(p, "all.zip"):
		w.WriteHeader(http.StatusOK)
		n := strings.ToLower(path.Dir(p)[1:]) + ".zip"
		a.Logf("serving %q", n)
		if f, err := sys.Open(n); errors.Is(err, nil) {
			defer f.Close()
			if _, err := io.Copy(w, f); err != nil {
				a.Error(err)
			}
			return
		}
		z := zip.NewWriter(w)
		if err := z.SetComment("empty zip"); err != nil {
			a.Error(err)
		}
		if err := z.Close(); err != nil {
			a.Error(err)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestParse(t *testing.T) {
	srv := httptest.NewServer(&apiStub{t, ""})
	defer srv.Close()
	ctx := zlog.Test(context.Background(), t)

	u := updater{}
	cfgFunc := func(v interface{}) error {
		cfg := v.(*Config)
		cfg.URL = srv.URL
		return nil
	}
	if err := u.Configure(ctx, cfgFunc, srv.Client()); err != nil {
		t.Error(err)
	}

	rc, _, err := u.Fetch(ctx, driver.Fingerprint(""))
	if err != nil {
		t.Error(err)
	}
	defer rc.Close()
	vs, err := u.Parse(ctx, rc)
	if err != nil {
		t.Error(err)
	}
	t.Logf("parsed %d vulnerabilities", len(vs))
	if len(vs) != 0 {
		t.Log("first one:")
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "\t")
		if err := enc.Encode(vs[0]); err != nil {
			t.Error(err)
		}
		t.Log(buf.String())
	}
}
