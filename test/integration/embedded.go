package integration

import (
	"archive/tar"
	"archive/zip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ulikunitz/xz"

	"github.com/quay/claircore/internal/xmlutil"
)

// MavenBOM is the bill-of-materials reported by maven.
//
//	<metadata>
//	  <groupId>io.zonky.test.postgres</groupId>
//	  <artifactId>embedded-postgres-binaries-bom</artifactId>
//	  <versioning>
//	    <latest>16.1.0</latest>
//	    <release>16.1.0</release>
//	    <versions>
//	      <version>16.1.0</version>
//	    </versions>
//	    <lastUpdated>20231111034502</lastUpdated>
//	  </versioning>
//	</metadata>
type mavenBOM struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Versioning struct {
		Latest      string   `xml:"latest"`
		Release     string   `xml:"release"`
		LastUpdated int64    `xml:"lastUpdated"`
		Versions    []string `xml:"versions>version"`
	} `xml:"versioning"`
}

type fetchDescriptor struct {
	OS          string
	Arch        string
	Version     string
	RealVersion string
	cached      atomic.Bool
}

var embedDB = fetchDescriptor{
	OS:      runtime.GOOS,
	Arch:    findArch(), // This is a per-OS function.
	Version: `latest`,
}

func init() {
	// See if a different version was requested.
	if e := os.Getenv(EnvPGVersion); e != "" {
		embedDB.Version = e
	}
}

func startEmbedded(t testing.TB) func() {
	if os.Getuid() == 0 {
		// Print warning to prevent wary travelers needing to go spelunking in
		// the logs.
		t.Log("⚠️ PostgreSQL refuses to start as root; this will almost certainly not work ⚠️")
	}
	if embedDB.Arch == "" {
		t.Logf(`⚠️ unsupported platform "%s/%s"; see https://mvnrepository.com/artifact/io.zonky.test.postgres/embedded-postgres-binaries-bom`,
			runtime.GOOS, runtime.GOARCH,
		)
		t.Log("See the test/integration documentation for how to specify an external database.")
		t.FailNow()
	}
	return func() {
		pkgDB = &Engine{}
		if err := pkgDB.Start(t); err != nil {
			t.Log("unclean shutdown?", err)
			if err := pkgDB.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := pkgDB.Start(t); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := pgxpool.ParseConfig(pkgDB.DSN)
		if err != nil {
			t.Error(err)
			return
		}
		pkgConfig = cfg
	}
}

func (a *fetchDescriptor) URL(t testing.TB) string {
	const (
		repo    = `https://repo1.maven.org`
		pathFmt = `/maven2/io/zonky/test/postgres/embedded-postgres-binaries-%s-%s/%s/embedded-postgres-binaries-%[1]s-%s-%s.jar`
	)
	u, err := url.Parse(repo)
	if err != nil {
		t.Fatal(err)
	}
	u, err = u.Parse(fmt.Sprintf(pathFmt, a.OS, a.Arch, a.RealVersion))
	if err != nil {
		t.Fatal(err)
	}
	return u.String()
}

func (a *fetchDescriptor) Path(t testing.TB) string {
	return filepath.Join(CacheDir(t), fmt.Sprintf("postgres-%s-%s-%s", a.OS, a.Arch, a.Version))
}

func (a *fetchDescriptor) Realpath(t testing.TB) string {
	if a.RealVersion == "" {
		panic("realpath called before real version determined")
	}
	return filepath.Join(CacheDir(t), fmt.Sprintf("postgres-%s-%s-%s", a.OS, a.Arch, a.RealVersion))
}

// The URL that contains the list of available versions.
const bomURL = `https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-bom/maven-metadata.xml`

var versionRE = regexp.MustCompile(`^[0-9]+((\.[0-9]+){2})?$`)

func (a *fetchDescriptor) DiscoverVersion(t testing.TB) {
	if a.cached.Load() {
		// Should be fine.
		return
	}
	shouldFetch := false
	skip := skip()
	defer func() {
		if t.Failed() || t.Skipped() {
			a.cached.Store(false)
			return
		}
		a.cached.Store(!shouldFetch)
		if !shouldFetch {
			// If it does exist, wait until we can grab a shared lock. If this blocks,
			// it's because another process has the exclusive (write) lock. Any error
			// during this process just fails the test.
			lockDirShared(t, a.Realpath(t))
		}
		if a.Version != a.RealVersion {
			t.Logf("pattern %q resolved to version: %q", a.Version, a.RealVersion)
		}
	}()
	if testing.Short() {
		t.Skip("asked for short tests")
	}

	// Check if the version we've got is a pattern or a specific version:
	ms := versionRE.FindStringSubmatch(a.Version)
	switch {
	case a.Version == "latest":
		// OK
	case ms == nil:
		// Invalid
		t.Fatalf(`unknown version pattern %q; must be "\d+\.\d+\.\d+", "\d+", or "latest"`, a.Version)
	case ms[1] != "":
		// Full version
		a.RealVersion = a.Version
		_, err := os.Stat(a.Realpath(t))
		missing := errors.Is(err, fs.ErrNotExist)
		switch {
		case !missing: // OK
		case skip:
			t.Skip("skipping integration test: would need to fetch binaries")
		case !skip:
			shouldFetch = true
		}
		return
	default:
		// Pattern
	}

	// Execution being here means "Version" is a pattern, so the path reported
	// by [fetchDescriptor.Path] should be a symlink.

	fi, linkErr := os.Lstat(a.Path(t))
	_, dirErr := os.Stat(a.Path(t))
	missing := errors.Is(linkErr, fs.ErrNotExist) || errors.Is(dirErr, fs.ErrNotExist)
	fresh := false
	if fi != nil {
		if fi.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("path %q is not a symlink", a.Path(t))
		}
		const week = 7 * 24 * time.Hour
		fresh = fi.ModTime().After(time.Now().Add(-1 * week))
	}

	const week = 7 * 24 * time.Hour
	var bom mavenBOM
	var dec *xml.Decoder
	switch {
	case skip && missing:
		t.Skip("skipping integration test: would need to fetch bom & binaries")
	case !skip && !missing && fresh:
		fallthrough
	case skip && !missing:
		if a.RealVersion != "" {
			return
		}
		// If a symlink exists, read the pointed-to version and we're done.
		dst, err := os.Readlink(a.Path(t))
		if err != nil {
			t.Fatal(err)
		}
		i := strings.LastIndexByte(dst, '-')
		a.RealVersion = dst[i+1:]
		return
	case !skip && !missing && !fresh:
		fallthrough
	case !skip && missing:
		res, err := http.Get(bomURL) // Use of http.DefaultClient guarded by integration.Skip call.
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected response: %v", res.Status)
		}
		dec = xml.NewDecoder(res.Body)
	}

	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&bom); err != nil {
		t.Fatal(err)
	}

	if a.Version == "latest" {
		a.RealVersion = bom.Versioning.Latest
	} else {
		prefix := a.Version + "."
		vs := bom.Versioning.Versions
		for i := len(vs) - 1; i >= 0; i-- {
			v := vs[i]
			if strings.HasPrefix(v, prefix) {
				a.RealVersion = v
				break
			}
		}
	}
	if a.RealVersion == "" {
		t.Fatalf("unable to find a version for %q", a.Version)
	}

	_, linkErr = os.Stat(a.Realpath(t))
	shouldFetch = errors.Is(linkErr, os.ErrNotExist)
}

func (a *fetchDescriptor) FetchArchive(t testing.TB) {
	if a.cached.Load() {
		return
	}
	p := a.Realpath(t)

	if a.Version != a.RealVersion {
		link := a.Path(t)
		t.Logf("adding symlink %q → %q", link, p)
		os.Remove(link)
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(p, link); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Error(err)
		}
	}
	if !lockDir(t, p) {
		return
	}

	// Fetch and buffer the jar.
	u := a.URL(t)
	t.Logf("fetching %q", u)
	res, err := http.Get(u) // Use of http.DefaultClient guarded by integration.Skip call.
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %v", res.Status)
	}
	t.Log("fetch OK")
	jf, err := os.CreateTemp(t.TempDir(), "embedded-postgres.")
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
		outName := filepath.Join(p, normPath(h.Name))
		// Experimentally, these are the types we need to support when
		// extracting the tarballs.
		//
		// All the Mkdir calls are because tar, as a format, doesn't enforce
		// ordering, e.g. an entry for `a/b/c` and then `a/` is valid.
		//
		// This also plays fast and loose with permissions around directories.
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(outName, 0o755); err != nil {
				t.Error(err)
			}
			if err := os.Chmod(outName, h.FileInfo().Mode()); err != nil {
				t.Error(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(outName), 0o755); err != nil {
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
			if err := os.MkdirAll(filepath.Dir(outName), 0o755); err != nil {
				t.Error(err)
			}
			tgt := filepath.Join(filepath.Dir(outName), normPath(h.Linkname))
			if err := os.Symlink(tgt, outName); err != nil {
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

func normPath(p string) string {
	return filepath.Join("/", p)[1:]
}
