package magika

import (
	"archive/zip"
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
	base, err := getAPIBase()
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
	api, err := getAPI()
	if err != nil {
		t.Error(err)
	}
	if api == nil {
		t.Error("unexpected nil pointer return")
	}
}

func TestMagika(t *testing.T) {
	loadRuntime(t)
	modelZip := test.GenerateFixture(t, "magika_model.zip", time.Time{}, GenerateModelZip)
	if t.Failed() {
		return
	}

	f, fi := openStat(t, modelZip)
	z, err := zip.NewReader(f, fi.Size())
	if err != nil {
		t.Fatal(err)
	}

	m, err := LoadModel(z, `standard_v3_3`)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name string
		Want string
	}{
		{Name: "magika.go", Want: "text/x-golang"},
		{Name: modelZip, Want: "application/zip"},
	} {
		n := filepath.Base(tc.Name)
		t.Run(n, func(t *testing.T) {
			t.Logf("checking file %q", tc.Name)
			f, fi = openStat(t, tc.Name)
			ct, err := m.Scan(f, fi.Size())
			if err != nil {
				t.Error(err)
			}
			got, want := ct.MimeType, tc.Want
			t.Logf("got: %q, want: %q", got, want)
			if got != want {
				t.Fail()
			}
		})
	}
}

// Open and stats the named file, returning both.
//
// Fails and exits the test on error.
// Arranges for the file to be closed in a [testing.TB.Cleanup] function.
func openStat(t testing.TB, name string) (*os.File, os.FileInfo) {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("closing file %q: %v", f.Name(), err)
		}
	})
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return f, fi
}

func GenerateModelZip(t testing.TB, f *os.File) {
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
}
