package claircore

import (
	"archive/tar"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarTestCase struct {
	Name string
	// File is a slice of name, contents pairs.
	File [][2]string
	// Symlink is a slice of name, target pairs.
	Symlink [][2]string
	Check   func(*testing.T, *Layer)
}

func (tc tarTestCase) filename() string {
	return filepath.Join("testdata", "TestTar_"+tc.Name+".tar")
}

func (tc tarTestCase) Generate(t *testing.T) {
	if _, err := os.Stat(tc.filename()); err == nil {
		// already exists
		return
	}
	t.Logf("generating %q", tc.filename())
	defer func() {
		if t.Failed() {
			os.Remove(tc.filename())
		}
	}()

	f, err := os.Create(tc.filename())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	w := tar.NewWriter(f)
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()

	h := tar.Header{
		Uid:  1000,
		Gid:  1000,
		Mode: 0644,
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
	h.Mode = 0777
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
}

func (tc tarTestCase) Layer(t *testing.T) *Layer {
	tc.Generate(t)
	l := Layer{
		URI: "file:///dev/null",
	}
	var err error
	l.Hash, err = NewDigest("sha256", make([]byte, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetLocal(tc.filename()); err != nil {
		t.Fatal(err)
	}
	return &l
}

func (tc tarTestCase) Run(t *testing.T) {
	tc.Check(t, tc.Layer(t))
}

// TestTar contains tests around walking tar files.
func TestTar(t *testing.T) {
	var tbl = []tarTestCase{
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
				var want = "contents\n"
				var names = []string{`symlink1`, `symlink2`, `symlink3`}
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
				var want = "contents\n"
				var names = []string{`symlink1`, `basic`}
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
				var names = []string{`symlink1`}
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
				var names = []string{`symlink`}
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
				var want = "contents\n"
				var names = []string{`../../../../target`}
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
