package jar

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
)

//go:generate go run fetch_testdata.go

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	const url = `https://archive.apache.org/dist/cassandra/4.0.0/apache-cassandra-4.0.0-bin.tar.gz`
	const sha = `2ff17bda7126c50a2d4b26fe6169807f35d2db9e308dc2851109e1c7438ac2f1`
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
		if !checkExt(h.Name) {
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
			case errors.Is(err, ErrUnidentified):
				t.Log(err)
			case filepath.Base(h.Name) == "javax.inject-1.jar" && errors.Is(err, ErrNotAJar):
				// This is an odd one, it has no metadata.
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
	ps, err := Parse(ctx, name, z)
	switch {
	case errors.Is(err, nil):
		for _, p := range ps {
			t.Log(p.String())
		}
	case errors.Is(err, ErrUnidentified):
		t.Error(err)
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
	name = filepath.Join("testdata", path.Base(uri.Path))
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
		res, err := http.Get(uri.String())
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
				t.Fatal(err)
			}
			defer f.Close()
			fi, err := ent.Info()
			if err != nil {
				t.Fatal(err)
			}
			sz := fi.Size()
			buf.Reset()
			buf.Grow(int(sz))
			if _, err := buf.ReadFrom(f); err != nil {
				t.Error(err)
			}

			z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), fi.Size())
			if err != nil {
				t.Error(err)
			}
			i, err := Parse(ctx, n, z)
			if err != nil {
				t.Error(err)
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
			ms = append(ms, filepath.Join("testdata", p, e.Name()))
		}
	}

	for _, n := range ms {
		n := n
		t.Run(filepath.Base(n), func(t *testing.T) {
			f, err := os.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// 72 is the line length limit, so this means the section reader is
			// going to see only chunks of a line on every read.
			m := newMainSectionReader(bufio.NewReaderSize(f, 64))
			var buf bytes.Buffer
			n, err := io.Copy(&buf, m)
			t.Logf("read %d bytes", n)
			if err != nil {
				t.Error(err)
			}
			t.Logf("read: %+#q", buf.String())
			msg, err := mail.ReadMessage(&buf)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("headers: %+v", msg.Header)
			if _, ok := msg.Header["Name"]; ok {
				t.Error(`key "Name" exists when it shouldn't`)
			}
			if _, ok := msg.Header["Manifest-Version"]; !ok {
				t.Error(`key "Manifest-Version" does not exist`)
			}
		})
	}
}
