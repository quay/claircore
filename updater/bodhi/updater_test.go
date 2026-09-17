package bodhi

import (
	"archive/zip"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	driver "github.com/quay/claircore/updater/driver/v1"
	"github.com/quay/zlog"
)

func TestUpdater(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	tmp := t.TempDir()
	srv := httptest.NewServer(mockBodhi(t))
	defer srv.Close()

	var us []driver.Updater
	t.Run("Factory", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		cf := func(v interface{}) error {
			v.(*FactoryConfig).API = &srv.URL
			return nil
		}
		fac, err := NewFactory(ctx)
		if err != nil {
			t.Error(err)
		}
		us, err = fac.Create(ctx, cf)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Fetch", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		for _, u := range us {
			zf, err := os.Create(filepath.Join(tmp, url.PathEscape(u.Name())))
			if err != nil {
				t.Fatal(err)
			}
			defer zf.Close()
			z := zip.NewWriter(zf)
			fp, err := u.Fetch(ctx, z, driver.Fingerprint(""), srv.Client())
			if err != nil {
				t.Error(err)
			}
			t.Logf(`%#v`, fp)
			if err := z.Close(); err != nil {
				t.Error(err)
			}
		}

		for _, u := range us {
			zf, err := os.Open(filepath.Join(tmp, url.PathEscape(u.Name())))
			if err != nil {
				t.Fatal(err)
			}
			defer zf.Close()

			fi, err := zf.Stat()
			if err != nil {
				t.Error(err)
			}
			zr, err := zip.NewReader(zf, fi.Size())
			if err != nil {
				t.Error(err)
			}
			for _, f := range zr.File {
				t.Logf("zip:%s", f.Name)
			}
			if len(zr.File) == 0 {
				t.Error("wanted more than 0 files")
			}
		}
	})

	t.Run("Parse", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		for _, u := range us {
			vp := u.(driver.VulnerabilityParser)
			zf, err := os.Open(filepath.Join(tmp, url.PathEscape(u.Name())))
			if err != nil {
				t.Fatal(err)
			}
			defer zf.Close()

			fi, err := zf.Stat()
			if err != nil {
				t.Error(err)
			}
			z, err := zip.NewReader(zf, fi.Size())
			if err != nil {
				t.Error(err)
			}
			pv, err := vp.ParseVulnerability(ctx, z)
			if err != nil {
				t.Error(err)
			}
			t.Logf("%#v", pv)
		}
	})
}

func mockBodhi(t *testing.T) http.Handler {
	return mockServer{
		FS: os.DirFS(`testdata/updater`),
		t:  t,
	}
}

type mockServer struct {
	fs.FS
	t *testing.T
}

func (srv mockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case `/releases`:
		w.Header().Set(`content-type`, `application/json`)
		f, err := srv.FS.Open("releases.json")
		if err != nil {
			srv.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, "", time.Now(), f.(io.ReadSeeker))
	case `/updates`:
		w.Header().Set(`content-type`, `application/json`)
		rls := r.URL.Query().Get("release")
		pg := r.URL.Query().Get("page")
		if pg == "" {
			pg = "0"
		}
		f, err := srv.FS.Open(path.Join(rls, "updates.json."+pg))
		if err != nil {
			srv.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, "", time.Now(), f.(io.ReadSeeker))
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
	return
}
