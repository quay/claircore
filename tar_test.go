package claircore

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore/toolkit/spool"
	"github.com/quay/zlog"
)

type tarTestCase struct {
	Check func(*testing.T, *Layer)
	Name  string
	// File is a slice of name, contents pairs.
	File [][2]string
	// Symlink is a slice of name, target pairs.
	Symlink [][2]string
}

func (tc tarTestCase) filename() string {
	return filepath.Join("testdata", "TestTar_"+tc.Name+".tar")
}

func (tc tarTestCase) Generate(t *testing.T, a *spool.Arena) *spool.File {
	ctx := zlog.Test(context.Background(), t)
	f, err := a.NewSpool(ctx, "tar.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Logf("generating %q", f.Name())
	w := tar.NewWriter(f)
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()

	h := tar.Header{
		Uid:  1000,
		Gid:  1000,
		Mode: 0o644,
	}
	for _, pair := range tc.File {
		rd := strings.NewReader(pair[1])
		h = tar.Header{
			Typeflag: tar.TypeReg,
			Name:     pair[0],
			Size:     rd.Size(),
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := rd.WriteTo(w); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %q", pair[0])
	}
	h.Mode = 0o777
	for _, pair := range tc.Symlink {
		h = tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     pair[0],
			Linkname: pair[1],
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %q", pair[0])
	}
	return f
}

func (tc tarTestCase) Layer(t *testing.T, a *spool.Arena) *Layer {
	l := Layer{
		URI: "file:///dev/null",
	}
	l.file = tc.Generate(t, a)
	var err error
	l.Hash, err = NewDigest("sha256", make([]byte, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	return &l
}

func (tc tarTestCase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	root := t.TempDir()
	a, err := spool.NewArena(ctx, root, "arena")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tc.Check(t, tc.Layer(t, a))
}

// TestTar contains tests around walking tar files.
func TestTar(t *testing.T) {
	tbl := []tarTestCase{
		{
			Name: "Simple",
			File: [][2]string{
				{"basic", "contents\n"},
			},
			Check: func(t *testing.T, l *Layer) {
				const name = "basic"
				t.Logf("%+#v", l)

				m, err := l.Files(name)
				if err != nil {
					t.Error(err)
				}
				r, ok := m[name]
				if !ok {
					t.Fatalf("file not found: %q", name)
				}
				if got, want := r.String(), "contents\n"; got != want {
					t.Fatalf("got: %q, want: %q", got, want)
				}
			},
		},
		{
			Name: "SimpleSymlink",
			File: [][2]string{
				{"basic", "contents\n"},
			},
			Symlink: [][2]string{
				{"symlink1", "/basic"},
				{"symlink2", "./basic"},
				{"symlink3", "basic"},
			},
			Check: func(t *testing.T, l *Layer) {
				want := "contents\n"
				names := []string{`symlink1`, `symlink2`, `symlink3`}
				t.Logf("%+#v", l)

				m, err := l.Files(names...)
				if err != nil {
					t.Error(err)
				}
				t.Logf("%+#v", m)
				for _, name := range names {
					r, ok := m[name]
					if !ok {
						t.Fatalf("file not found: %q", name)
					}
					if got := r.String(); got != want {
						t.Fatalf("got: %q, want: %q", got, want)
					}
				}
			},
		},
		{
			Name: "ChaseSymlink",
			File: [][2]string{
				{"basic", "contents\n"},
			},
			Symlink: [][2]string{
				{"symlink1", "/symlink2"},
				{"symlink2", "./symlink3"},
				{"symlink3", "basic"},
			},
			Check: func(t *testing.T, l *Layer) {
				want := "contents\n"
				names := []string{`symlink1`, `basic`}
				t.Logf("%+#v", l)

				m, err := l.Files(names...)
				if err != nil {
					t.Error(err)
				}
				t.Logf("%+#v", m)
				for _, name := range names {
					r, ok := m[name]
					if !ok {
						t.Fatalf("file not found: %q", name)
					}
					if got := r.String(); got != want {
						t.Fatalf("got: %q, want: %q", got, want)
					}
				}
			},
		},
		{
			Name: "DanglingSymlink",
			Symlink: [][2]string{
				{"symlink1", "/symlink2"},
				{"symlink2", "./symlink3"},
				{"symlink3", "basic"},
			},
			Check: func(t *testing.T, l *Layer) {
				names := []string{`symlink1`}
				t.Logf("%+#v", l)

				if _, err := l.Files(names...); err == nil {
					t.Fatal("got: <nil>, want: error")
				}
			},
		},
		{
			Name: "EscapingSymlink",
			Symlink: [][2]string{
				{"symlink", "../../../../target"},
			},
			Check: func(t *testing.T, l *Layer) {
				names := []string{`symlink`}
				t.Logf("%+#v", l)

				if _, err := l.Files(names...); err == nil {
					t.Fatal("got: <nil>, want: error")
				}
			},
		},
		{
			Name: "EscapingRequest",
			File: [][2]string{
				{"target", "contents\n"},
			},
			Check: func(t *testing.T, l *Layer) {
				want := "contents\n"
				names := []string{`../../../../target`}
				t.Logf("%+#v", l)

				m, err := l.Files(names...)
				if err != nil {
					t.Error(err)
				}
				t.Logf("%+#v", m)
				for _, name := range names {
					r, ok := m[name]
					if !ok {
						t.Fatalf("file not found: %q", name)
					}
					if got := r.String(); got != want {
						t.Fatalf("got: %q, want: %q", got, want)
					}
				}
			},
		},
	}

	defer func() {
		if t.Failed() {
			t.Log("a subtest failed, cleaning cached tarballs")
			fs, _ := filepath.Glob("testdata/TestTar_*.tar")
			for _, f := range fs {
				os.Remove(f)
			}
		}
	}()
	for _, tc := range tbl {
		t.Run(tc.Name, tc.Run)
	}
}
