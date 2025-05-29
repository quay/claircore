package magika

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

func loadRuntime(t testing.TB) {
	t.Helper()
	_, err := getRuntimeHandle()
	if err == nil {
		return
	}
	t.Skipf("unable to load ONNX runtime: %v", err)
}

func TestLoadRuntime(t *testing.T) {
	loadRuntime(t)
	t.Logf("runtime loaded")
}

func TestApiBase(t *testing.T) {
	loadRuntime(t)
	base, err := getapibase()
	if err != nil {
		t.Error(err)
	}
	if base == nil {
		t.Error("unexpected nil pointer return")
	}
	t.Logf("got version: %q", base.GetVersionString())
}

func TestGetApi(t *testing.T) {
	loadRuntime(t)
	api, err := getapi()
	if err != nil {
		t.Error(err)
	}
	if api == nil {
		t.Error("unexpected nil pointer return")
	}
}

func TestMagika(t *testing.T) {
	modelZip := test.GenerateFixture(t, "magika_model.zip", time.Time{},
		func(t testing.TB, f *os.File) {
			integration.Skip(t)
			const arURL = `https://github.com/google/magika/archive/refs/heads/main.zip`

			zf, err := os.Create(filepath.Join(t.TempDir(), `main.zip`))
			if err != nil {
				t.Fatal(err)
			}
			defer zf.Close()

			res, err := http.Get(arURL)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("unexpected response: %v", res.Status)
			}
			sz, err := io.Copy(zf, res.Body)
			if err != nil {
				t.Fatal(err)
			}

			zr, err := zip.NewReader(zf, sz)
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(f)
			defer zw.Close()

			for _, f := range zr.File {
				const prefix = `magika-main/assets/`
				if !strings.HasPrefix(f.Name, prefix) {
					continue
				}
				switch ext := path.Ext(f.Name); {
				case strings.HasSuffix(f.Name, "/"):
				case ext == ".onnx":
				case ext == ".json":
				default:
					continue
				}
				f.Name = strings.TrimPrefix(f.Name, prefix)
				if f.Name == "" {
					continue
				}
				t.Log(f.Name)

				if err := zw.Copy(f); err != nil {
					t.Fatal(err)
				}
			}
		},
	)
	if t.Failed() {
		return
	}

	f, err := os.Open(modelZip)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(f, fi.Size())
	if err != nil {
		t.Fatal(err)
	}

	m, err := LoadModel(z, `standard_v3_3`)
	if err != nil {
		t.Fatal(err)
	}

	const name = `magika.go`
	t.Logf("checking file %q", name)
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	rd := bytes.NewReader(b)
	ct, err := m.Scan(rd, rd.Size())
	if err != nil {
		t.Error(err)
	}
	t.Logf("got ContentType: %v", ct)
}
