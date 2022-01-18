package integration

import (
	"archive/tar"
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// Engine is a helper for managing a postgres engine.
type Engine struct {
	DSN     string
	binroot string
	port    string
	dataDir string
}

func (e *Engine) init(t testing.TB) {
	if binUncached(t) {
		fetchArchive(t)
	}
	d, err := cachedDir()
	if err != nil {
		t.Error(err)
	}
	e.binroot = filepath.Join(d, "bin")
	t.Logf("using binaries at %q", e.binroot)

	e.port = strconv.Itoa((os.Getpid() % 10000) + 30000)
	var dsn strings.Builder
	dsn.WriteString("host=localhost user=postgres password=securepassword sslmode=disable port=")
	dsn.WriteString(e.port)
	e.DSN = dsn.String()
	t.Logf("using port %q", e.port)

	e.dataDir = filepath.Join("testdata", "pg"+dbVersion)
	if _, err := os.Stat(e.dataDir); err == nil {
		t.Log("data directory exists, skipping initdb")
		// Should be set up already.
		return
	}
	t.Logf("using data directory %q", e.dataDir)
	pwfile := filepath.Join(t.TempDir(), "passwd")
	if err := ioutil.WriteFile(pwfile, []byte(`securepassword`), 0644); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll("testdata", 0755)
	log, err := os.Create(filepath.Join("testdata", "pg"+dbVersion+".initdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	t.Logf("log at %q", log.Name())

	cmd := exec.Command(filepath.Join(e.binroot, "initdb"),
		"--auth=password",
		"--username=postgres",
		"--pgdata="+e.dataDir,
		"--pwfile="+pwfile,
	)
	cmd.Stdout = log
	cmd.Stderr = log
	t.Logf("running %v", cmd.Args)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

// Start configures and starts the database engine.
//
// This should not be called multiple times.
func (e *Engine) Start(t testing.TB) error {
	e.init(t)
	cmd := exec.Command(filepath.Join(e.binroot, "pg_ctl"),
		"-w",
		"-s",
		"-D", e.dataDir,
		"-l", filepath.Join(e.dataDir, "log"),
		"-o", "-F -p "+e.port,
		"start",
	)
	t.Logf("starting database engine: %v", cmd.Args)
	return cmd.Run()
}

// Stop stops the database engine.
//
// It's an error to call Stop before a successful Start.
func (e *Engine) Stop() error {
	cmd := exec.Command(filepath.Join(e.binroot, "pg_ctl"),
		"-w",
		"-s",
		"-D", e.dataDir,
		"-m", "fast",
		"stop",
	)
	return cmd.Run()
}

func fetchArchive(t testing.TB) {
	p, err := cachedDir()
	if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(p, 0755)
	}
	if !lockDir(t, p) {
		return
	}

	// Fetch and buffer the jar.
	u := downloadURL()
	t.Logf("fetching %q", u)
	res, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %v", res.Status)
	}
	t.Log("fetch OK")
	jf, err := ioutil.TempFile(t.TempDir(), "embedded-postgres.")
	if err != nil {
		t.Fatal(err)
	}
	defer jf.Close()
	sz, err := io.Copy(jf, res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jf.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	// Open the jar (note a jar is just a zip with specific contents) and find
	// the tarball.
	r, err := zip.NewReader(jf, sz)
	if err != nil {
		t.Fatal(err)
	}
	var zf *zip.File
	for _, h := range r.File {
		if !strings.HasSuffix(h.Name, ".txz") {
			continue
		}
		zf = h
		break
	}
	if zf == nil {
		t.Fatal("didn't find txz")
	}

	// Extract the tarball to the target directory.
	t.Logf("extracting %q to %q", zf.Name, p)
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Error(err)
	}
	rd, err := zf.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	tf, err := xz.NewReader(rd)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(tf)
	var h *tar.Header
	for h, err = tr.Next(); err == nil && !t.Failed(); h, err = tr.Next() {
		outName := filepath.Join(p, h.Name)
		// Experimentally, these are the types we need to support when
		// extracting the tarballs.
		//
		// All the Mkdir calls are because tar, as a format, doesn't enforce
		// ordering, e.g. an entry for `a/b/c` and then `a/` is valid.
		//
		// This also plays fast and loose with permissions around directories.
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(outName, 0755); err != nil {
				t.Error(err)
			}
			if err := os.Chmod(outName, h.FileInfo().Mode()); err != nil {
				t.Error(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(outName), 0755); err != nil {
				t.Error(err)
			}
			f, err := os.Create(outName)
			if err != nil {
				t.Error(err)
			}
			// Don't defer the Close, make sure we're unconditionally closing
			// the file on every loop.
			if _, err := io.Copy(f, tr); err != nil {
				t.Error(err)
			}
			if err := f.Chmod(h.FileInfo().Mode()); err != nil {
				t.Error(err)
			}
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(outName), 0755); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(h.Linkname, outName); err != nil {
				t.Error(err)
			}
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if err != io.EOF {
		t.Fatal(err)
	}
	t.Log("extraction OK")
}

func binUncached(t testing.TB) bool {
	t.Helper()
	// If the directory doesn't exist, report that it's uncached.
	p, err := cachedDir()
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	// If it does exist, wait until we can grab a shared lock. If this blocks,
	// it's because another process has the exclusive (write) lock. Any error
	// during this process just fails the test.
	lockDirShared(t, p)
	return false
}

func cachedDir() (string, error) {
	c, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(c, "clair-testing", fmt.Sprintf("postgres-%s-%s-%s", dbOS, dbArch, dbVersion))
	_, err = os.Stat(p)
	if err != nil {
		return p, err
	}
	return p, nil
}

func downloadURL() string {
	// Since these are a constant and a format string with what should be a
	// constrained set of inputs, just panic if the functions we feed them into
	// report errors.
	const (
		repo    = `https://repo1.maven.org`
		pathFmt = `/maven2/io/zonky/test/postgres/embedded-postgres-binaries-%s-%s/%s/embedded-postgres-binaries-%[1]s-%s-%s.jar`
	)
	u, err := url.Parse(repo)
	if err != nil {
		panic(err)
	}
	u, err = u.Parse(fmt.Sprintf(pathFmt, dbOS, dbArch, dbVersion))
	if err != nil {
		panic(err)
	}
	return u.String()
}
