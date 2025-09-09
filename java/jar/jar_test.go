package jar

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

//go:generate go run fetch_testdata.go

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	const url = `https://repo1.maven.org/maven2/com/orientechnologies/orientdb-community/3.2.37/orientdb-community-3.2.37.tar.gz`
	const sha = `101d93340ae17cfdc622ef37e30c8c3993874ab199fd5ff3fc76d466740fefe3`
	name := fetch(t, url, sha)

	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var h *tar.Header
	var buf bytes.Buffer
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		if !ValidExt(h.Name) {
			continue
		}
		t.Log("found jar:", h.Name)
		t.Run(filepath.Base(h.Name), func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			buf.Reset()
			buf.Grow(int(h.Size))
			n, err := io.Copy(&buf, tr)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("read: %d bytes", n)
			z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatal(err)
			}
			ps, err := Parse(ctx, h.Name, z)
			switch {
			case errors.Is(err, nil):
				t.Log(ps)
			case (filepath.Base(h.Name) == "graal-sdk-21.3.5.jar" ||
				filepath.Base(h.Name) == "regex-21.3.5.jar" ||
				filepath.Base(h.Name) == "js-scriptengine-21.3.5.jar" ||
				filepath.Base(h.Name) == "profiler-21.3.5.jar") && errors.Is(err, ErrNotAJar):
				// These are odd ones, there's no MANIFEST.MF or pom.properties files.
				t.Log(err)
			default:
				t.Errorf("unexpected: %v", err)
			}
		})
	}
	if err != io.EOF {
		t.Error(err)
	}
}

func TestWAR(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	const url = `https://get.jenkins.io/war/2.311/jenkins.war`
	const sha = `fe21501800c769279699ecf511fd9b495b1cb3ebd226452e01553ff06820910a`
	name := fetch(t, url, sha)

	f, err := os.Open(name)
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
		t.Error(err)
	}
	ps, err := Parse(ctx, filepath.Base(name), z)
	switch {
	case errors.Is(err, nil):
		for _, p := range ps {
			t.Log(p.String())
		}
	default:
		t.Errorf("unexpected: %v", err)
	}
}

func fetch(t testing.TB, u string, ck string) (name string) {
	t.Helper()
	uri, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	name = filepath.Join(integration.PackageCacheDir(t), path.Base(uri.Path))
	ckb, err := hex.DecodeString(ck)
	if err != nil {
		t.Fatal(err)
	}

	switch _, err := os.Stat(name); {
	case errors.Is(err, nil):
		t.Logf("file %q found", name)
	case errors.Is(err, os.ErrNotExist):
		t.Logf("file %q missing", name)
		integration.Skip(t)
		res, err := http.Get(uri.String()) // Use of http.DefaultClient guarded by integration.Skip call.
		if err != nil {
			t.Error(err)
			break
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("unexpected HTTP status: %v", res.Status)
			break
		}
		o, err := os.Create(name)
		if err != nil {
			t.Error(err)
			break
		}
		defer o.Close()
		h := sha256.New()
		if _, err := io.Copy(o, io.TeeReader(res.Body, h)); err != nil {
			t.Error(err)
		}
		o.Sync()
		if got, want := h.Sum(nil), ckb; !bytes.Equal(got, want) {
			t.Errorf("checksum mismatch; got: %x, want: %x", got, want)
		}
	default:
		t.Error(err)
	}
	if t.Failed() {
		if err := os.Remove(name); err != nil {
			t.Error(err)
		}
		t.FailNow()
	}
	t.Log("🆗")
	return name
}

func TestJAR(t *testing.T) {
	ctx := context.Background()
	td := os.DirFS("testdata/jar")
	ls, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) == 0 {
		t.Skip(`no jars found in "testdata" directory`)
	}

	var buf bytes.Buffer
	for _, ent := range ls {
		if !ent.Type().IsRegular() {
			continue
		}
		n := path.Base(ent.Name())
		if ok, _ := filepath.Match(".?ar", path.Ext(n)); !ok {
			continue
		}
		t.Run(n, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := td.Open(ent.Name())
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			fi, err := ent.Info()
			if err != nil {
				t.Error(err)
				return
			}
			sz := fi.Size()
			buf.Reset()
			buf.Grow(int(sz))
			if _, err := buf.ReadFrom(f); err != nil {
				t.Error(err)
				return
			}

			z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), fi.Size())
			if err != nil {
				t.Fatal(err)
				return
			}
			i, err := Parse(ctx, n, z)
			if err != nil {
				t.Error(err)
				return
			}
			for _, i := range i {
				t.Log(i.String())
			}
		})
	}
}

func TestJARBadManifest(t *testing.T) {
	ctx := context.Background()
	path := "testdata/malformed-manifests"
	d := os.DirFS(path)
	ls, err := fs.ReadDir(d, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) == 0 {
		t.Skip(`no jars found in "testdata" directory`)
	}

	for _, n := range ls {
		t.Log(n)
		t.Run(n.Name(), func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(filepath.Join(path, n.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			i := &Info{}
			err = i.parseManifest(ctx, f)
			if err != nil && !errors.Is(err, errInsaneManifest) {
				t.Fatal(err)
			}
		})
	}
}

// TestMalformed creates malformed zips, then makes sure the package handles
// them gracefully.
func TestMalformed(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	t.Run("BadOffset", func(t *testing.T) {
		const (
			jarName  = `malformed_zip.jar`
			manifest = `testdata/malformed_zip.MF`
		)
		fn := test.GenerateFixture(t, jarName, test.Modtime(t, "jar_test.go"), func(t testing.TB, f *os.File) {
			// Create the jar-like.
			w := zip.NewWriter(f)
			if _, err := w.Create(`META-INF/`); err != nil {
				t.Fatal(err)
			}
			fw, err := w.Create(`META-INF/MANIFEST.MF`)
			if err != nil {
				t.Fatal(err)
			}
			mf, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(fw, bytes.NewReader(mf)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			// Then, corrupt it.
			// Seek to the central directory footer:
			pos, err := f.Seek(-0x16+0x10 /* sizeof(footer) + offset(dir_offset)*/, io.SeekEnd)
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 4)
			if _, err := io.ReadFull(f, b); err != nil {
				t.Fatal(err)
			}
			// Offset everything so the reader slowly descends into madness.
			b[0] -= 7
			if _, err := f.WriteAt(b, pos); err != nil {
				t.Fatal(err)
			}

			if err := f.Sync(); err != nil {
				t.Error(err)
			}
		})

		f, err := os.Open(fn)
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
		infos, err := Parse(ctx, jarName, z)
		t.Logf("returned error: %v", err)
		switch {
		case errors.Is(err, ErrNotAJar):
		default:
			t.Fail()
		}
		if len(infos) != 0 {
			t.Errorf("returned infos: %#v", infos)
		}
	})

	t.Run("Cursed", func(t *testing.T) {
		// Why is the footer corrupted like that?
		// No idea, we just found a jar in the wild that looked like this.
		fn := test.GenerateFixture(t, `plantar.jar`, test.Modtime(t, "jar_test.go"), func(t testing.TB, f *os.File) {
			const comment = "\x00"
			// Create the jar-like.
			w := zip.NewWriter(f)
			fw, err := w.Create(`META-INF/MANIFEST.MF`)
			if err != nil {
				t.Fatal(err)
			}
			mf, err := os.Open("testdata/manifest/HdrHistogram-2.1.9.jar")
			if err != nil {
				t.Fatal(err)
			}
			defer mf.Close()
			if _, err := io.Copy(fw, mf); err != nil {
				t.Fatal(err)
			}
			w.SetComment(comment)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			f.Write([]byte{0x00}) // Bonus!

			// Then, corrupt it.
			fi, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			ft := make([]byte, 0x16+int64(len(comment))+1)
			ftOff := fi.Size() - int64(len(ft))
			ptrOff := ftOff + 16
			szOff := ftOff + 12

			info := func() {
				if _, err := f.ReadAt(ft, ftOff); err != nil {
					t.Error(err)
				}
				t.Logf("footer:\n%s", hex.Dump(ft))
				b := make([]byte, 4)
				if _, err := f.ReadAt(b, ptrOff); err != nil {
					t.Fatal(err)
				}
				ptr := binary.LittleEndian.Uint32(b)
				t.Logf("Central Directory pointer: 0x%08x", ptr)
				b = b[:2]
				if _, err := f.ReadAt(b, szOff); err != nil {
					t.Fatal(err)
				}
				sz := binary.LittleEndian.Uint16(b)
				t.Logf("Central Directory size:    %d", sz)
			}

			info()
			if _, err := f.WriteAt([]byte{0xef, 0xbe, 0xad, 0xde}, ptrOff); err != nil {
				t.Error(err)
			}
			if _, err := f.WriteAt([]byte{0x20, 0x00}, szOff); err != nil {
				t.Error(err)
			}
			info()

			if err := f.Sync(); err != nil {
				t.Error(err)
			}
		})

		f, err := os.Open(fn)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		_, err = zip.NewReader(f, fi.Size())
		t.Logf("returned error: %v", err)
		switch {
		case errors.Is(err, io.EOF): // <= go1.20
		case errors.Is(err, zip.ErrFormat):
		default:
			t.Fail()
		}
	})

}

func TestManifestSectionReader(t *testing.T) {
	var ms []string
	d := os.DirFS("testdata")
	for _, p := range []string{"manifest", "manifestSection"} {
		ents, err := fs.ReadDir(d, p)
		if err != nil {
			t.Error(err)
			return
		}
		for _, e := range ents {
			if filepath.Ext(e.Name()) == ".want" {
				continue
			}
			ms = append(ms, filepath.Join("testdata", p, e.Name()))
		}
	}

	for _, n := range ms {
		n := n
		t.Run(filepath.Base(n), func(t *testing.T) {
			wantF, err := os.Open(n + ".want")
			if err != nil {
				t.Error(err)
			}
			var want bytes.Buffer
			_, err = want.ReadFrom(wantF)
			wantF.Close()
			if err != nil {
				t.Error(err)
			}
			inF, err := os.Open(n)
			if err != nil {
				t.Error(err)
			}
			defer inF.Close()
			var out bytes.Buffer
			if _, err := io.Copy(&out, newMainSectionReader(inF)); err != nil {
				t.Error(err)
			}
			// Can't use iotest.TestReader because we disallow tiny reads.
			if got, want := out.String(), want.String(); !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func TestInnerJar(t *testing.T) {
	name := filepath.Join("testdata", "inner", "inner.jar")
	rc, err := zip.OpenReader(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
	})

	ctx := zlog.Test(context.Background(), t)
	got, err := Parse(ctx, name, &rc.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 {
		t.Errorf("got %d entries, expected 3", len(got))
	}

	want := []Info{
		{
			Name:    "jackson-annotations",
			Version: "2.13.0",
			Source:  ".",
		},
		{
			Name:    "log4j-api",
			Version: "2.14",
			Source:  ".",
		},
		{
			Name:    "log4j",
			Version: "2.14.0",
			Source:  ".",
		},
	}

	if !cmp.Equal(got, want, cmpopts.IgnoreFields(Info{}, "SHA")) {
		t.Error(cmp.Diff(got, want))
	}
}
