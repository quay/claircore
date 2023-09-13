package tarfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/quay/claircore/test/integration"
)

// TestFS runs some sanity checks on a tar generated from this package's
// directory.
//
// The tar is generated on demand and removed if tests fail, so modifying any
// file in this package *will* cause tests to fail once. Make sure to run tests
// twice if the Checksum tests fail.
func TestFS(t *testing.T) {
	var name = filepath.Join(integration.PackageCacheDir(t), `fstest.tar`)
	checktar(t, name)
	fileset := []string{
		"file.go",
		"parse.go",
		"tarfs.go",
		"tarfs_test.go",
		"testdata/atroot",
	}

	t.Run("Single", func(t *testing.T) {
		f, err := os.Open(name)
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		sys, err := New(f)
		if err != nil {
			t.Error(err)
		}

		if err := fstest.TestFS(sys, fileset...); err != nil {
			t.Error(err)
		}
	})

	t.Run("Concurrent", func(t *testing.T) {
		f, err := os.Open(name)
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		sys, err := New(f)
		if err != nil {
			t.Error(err)
		}

		const lim = 8
		var wg sync.WaitGroup
		t.Logf("running %d goroutines", lim)
		wg.Add(lim)
		for i := 0; i < lim; i++ {
			go func() {
				defer wg.Done()
				if err := fstest.TestFS(sys, fileset...); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("Sub", func(t *testing.T) {
		f, err := os.Open(name)
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		sys, err := New(f)
		if err != nil {
			t.Error(err)
		}

		sub, err := fs.Sub(sys, "testdata")
		if err != nil {
			t.Error(err)
		}
		if err := fstest.TestFS(sub, "atroot"); err != nil {
			t.Error(err)
		}
	})

	t.Run("Checksum", func(t *testing.T) {
		f, err := os.Open(name)
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		sys, err := New(f)
		if err != nil {
			t.Error(err)
		}
		for _, n := range fileset {
			name := n
			t.Run(name, func(t *testing.T) {
				h := sha256.New()
				f, err := os.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := io.Copy(h, f); err != nil {
					t.Error(err)
				}
				want := h.Sum(nil)

				h.Reset()
				b, err := fs.ReadFile(sys, name)
				if err != nil {
					t.Error(err)
				}
				if _, err := h.Write(b); err != nil {
					t.Error(err)
				}
				got := h.Sum(nil)

				if !bytes.Equal(got, want) {
					t.Errorf("got: %x, want: %x", got, want)
				}
			})
		}
	})
}

// TestEmpty tests that a wholly empty tar still creates an empty root.
func TestEmpty(t *testing.T) {
	// Two zero blocks is the tar footer, so just make one up.
	rd := bytes.NewReader(make([]byte, 2*512))
	sys, err := New(rd)
	if err != nil {
		t.Error(err)
	}
	if _, err := fs.Stat(sys, "."); err != nil {
		t.Error(err)
	}
	ent, err := fs.ReadDir(sys, ".")
	if err != nil {
		t.Error(err)
	}
	for _, e := range ent {
		t.Log(e)
	}
	if len(ent) != 0 {
		t.Errorf("got: %d, want: 0", len(ent))
	}
}

func checktar(t *testing.T, name string) {
	t.Helper()
	out, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	defer tw.Close()

	in := os.DirFS(".")
	if err := fs.WalkDir(in, ".", mktar(t, in, tw)); err != nil {
		t.Fatal(err)
	}
}

func mktar(t *testing.T, in fs.FS, tw *tar.Writer) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case filepath.Ext(d.Name()) == ".tar":
			return nil
		case d.Name() == "." && d.IsDir():
			return nil
		case d.Name() == "known" && d.IsDir():
			return fs.SkipDir
		default:
		}
		t.Logf("adding %q", p)
		i, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(i, "")
		if err != nil {
			return err
		}
		h.Name = p
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if i.IsDir() {
			return nil
		}
		f, err := in.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	}
}

func TestSymlinks(t *testing.T) {
	tmp := t.TempDir()
	run := func(openErr bool, hs []tar.Header, chk func(*testing.T, fs.FS)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
			// This is a perfect candidate for using test.GenerateFixture, but
			// creates an import cycle.
			f, err := os.Create(filepath.Join(tmp, path.Base(t.Name())))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			tw := tar.NewWriter(f)
			for i := range hs {
				if err := tw.WriteHeader(&hs[i]); err != nil {
					t.Error(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Error(err)
			}

			sys, err := New(f)
			t.Log(err)
			if (err != nil) != openErr {
				t.Fail()
			}

			if chk != nil {
				chk(t, sys)
			}
		}
	}

	t.Run("Ordered", run(false, []tar.Header{
		{Name: `a/`},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{Name: `b/c`},
	}, nil))
	t.Run("Unordered", run(false, []tar.Header{
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{Name: `b/c`},
		{Name: `a/`},
	}, nil))
	t.Run("LinkToReg", run(true, []tar.Header{
		{Name: `a`},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{Name: `b/c`},
	}, nil))
	t.Run("UnorderedLinkToReg", run(true, []tar.Header{
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{Name: `b/c`},
		{Name: `a`},
	}, nil))
	t.Run("Cycle", run(true, []tar.Header{
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `a`,
			Linkname: `b`,
		},
		{Name: `b/c`},
	}, nil))
	t.Run("ReplaceSymlink", run(false, []tar.Header{
		{Name: `a`},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `a`,
		},
		{Name: `b`},
	}, func(t *testing.T, sys fs.FS) {
		fi, err := fs.Stat(sys, "a")
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&fs.ModeType != 0 {
			t.Errorf("unexpected mode: %x", fi.Mode())
		}

		fi, err = fs.Stat(sys, "b")
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&fs.ModeType != fs.ModeSymlink {
			t.Errorf("unexpected mode: %x", fi.Mode())
		}
	}))
	t.Run("AbsLink", run(false, []tar.Header{
		{Name: `a/`},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `b`,
			Linkname: `/a`,
		},
		{Name: `b/c`},
	}, func(t *testing.T, sys fs.FS) {
		d, err := sys.Open("b")
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		fi, err := d.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Name() != "a" || !fi.IsDir() {
			t.Error("unexpected stat: ", fi.Name(), fi.IsDir())
		}
	}))
	// The following tests are ported from the claircore package.
	//
	// That package used to have enough smarts to extract files on its own, but
	// now uses [fs.FS], and the tar smarts live here.
	t.Run("ChaseSymlink", run(false, []tar.Header{
		{Name: "a", Mode: 0o777},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `1`,
			Linkname: `/2`,
		},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `2`,
			Linkname: `./3`,
		},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `3`,
			Linkname: `a`,
		},
	}, func(t *testing.T, sys fs.FS) {
		fi, err := fs.Stat(sys, "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("mode for %q: %v", "1", fi.Mode())
		if fi.Mode().Type()&fs.ModeSymlink == 0 { // If symlink bit unset.
			t.Fatal("cannot stat symlink: transparently followed")
		}
		fi, err = fs.Stat(sys, "a")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("mode for %q: %v", "a", fi.Mode())
		if fi.Mode().Type() != 0 { // If not a regular file
			t.Fatal("not a regular file")
		}
		if got, want := fi.Mode().Perm(), fs.FileMode(0o777); got != want {
			t.Fatalf("bad perms: got: %v, want: %v", got, want)
		}
		f, err := sys.Open("1")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fi, err = f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Type() != 0 { // If not a regular file
			t.Fatal("not a regular file")
		}
		if got, want := fi.Mode().Perm(), fs.FileMode(0o777); got != want {
			t.Fatalf("bad perms: got: %v, want: %v", got, want)
		}
	}))
	t.Run("DanglingSymlink", run(false, []tar.Header{
		{
			Typeflag: tar.TypeSymlink,
			Name:     `1`,
			Linkname: `/2`,
		},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `2`,
			Linkname: `./3`,
		},
		{
			Typeflag: tar.TypeSymlink,
			Name:     `3`,
			Linkname: `a`,
		},
	}, func(t *testing.T, sys fs.FS) {
		_, err := sys.Open("1")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("unexpected err return: %v", err)
		}
	}))
	t.Run("EscapingSymlink", run(false, []tar.Header{
		{
			Typeflag: tar.TypeSymlink,
			Name:     `1`,
			Linkname: `../../../../target`,
		},
	}, func(t *testing.T, sys fs.FS) {
		_, err := sys.Open("1")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("unexpected err return: %v", err)
		}
	}))
}

func TestKnownLayers(t *testing.T) {
	ents, err := os.ReadDir(`testdata/known`)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		n := ent.Name()
		if ext := filepath.Ext(n); ext != ".tar" && ext != ".layer" {
			continue
		}
		t.Run(n, func(t *testing.T) {
			f, err := os.Open(filepath.Join(`testdata/known`, n))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sys, err := New(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					t.Error(err)
				}
				fi, err := d.Info()
				if err != nil {
					t.Error(err)
				}
				if fi.Mode().Type()&fs.ModeSymlink != 0 {
					// Skip symlinks, because some layers just have them dangle.
					return nil
				}
				f, err := sys.Open(p)
				if err != nil {
					t.Error(err)
				}
				if f != nil {
					f.Close()
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestTarConcatenate tests the situation where a tar file is created (most
// likely with --concatenate or some variant) with symlink members in the path.
// The tar layout can be ostensibly "valid" but the fs it describes can be
// difficult to reason about.
//
// For example:
// ├── tar_1
// │   ├── run
// │   │   └── logs
// │   │       └── log.txt
// │   └── var
// │       └── run -> ../run
// ├── tar_2
// │   └── var
// │       └── run
// │           └── console
// │               └── algo.txt
//
// In both tars, `var/run` is defined, but once as a normal dir and once
// as a symlink to `../run`. For our sakes, we allow access through either
// the symlink path (`var/run` in this case) or the original dir path (`run/` in
// this case) for all files created under either path.
//
// For example, `algo.txt` can be accessed via `run/console/algo.txt` or
// `var/run/console/algo.txt` and `log.txt` can be accessed via `run/logs/log.txt`
// or `var/run/logs/log.txt`.
func TestTarConcatenate(t *testing.T) {
	tests := []struct {
		expectedFS map[string]bool
		testFile   string
	}{
		{
			expectedFS: map[string]bool{
				".":                        false,
				"run/console":              false,
				"run":                      false,
				"run/console/algo.txt":     false,
				"run/logs":                 false,
				"run/logs/log.txt":         false,
				"var":                      false,
				"var/run":                  false,
				"var/run/logs":             false,
				"var/run/console":          false,
				"var/run/console/algo.txt": false,
				"var/run/logs/log.txt":     false,
			},
			testFile: "testdata/concat.tar",
		},
	}

	for _, test := range tests {
		f, err := os.Open(test.testFile)
		if err != nil {
			t.Fatalf("failed to open test tar: %v", err)
		}
		sys, err := New(f)
		if err != nil {
			t.Fatalf("failed to create tarfs: %v", err)
		}
		if err := fs.WalkDir(sys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			t.Logf("path: %q", path)
			seen, ok := test.expectedFS[path]
			if !ok {
				t.Fatalf("didn't expect path %s", path)
			}
			if seen {
				t.Fatalf("we already saw this path: %s", path)
			}
			test.expectedFS[path] = true
			return nil
		}); err != nil {
			t.Errorf("error walking fs: %v\n", err)
			return
		}
		for fi := range test.expectedFS {
			if _, err := sys.Open(fi); err != nil {
				t.Errorf("could not open %s: %v", fi, err)
			}
		}
	}
}

func TestInvalidName(t *testing.T) {
	f, err := os.Open(`testdata/bad_name.tar`)
	if err != nil {
		t.Fatalf("failed to open test tar: %v", err)
	}
	defer f.Close()
	sys, err := New(f)
	if err != nil {
		t.Fatalf("failed to create tarfs: %v", err)
	}
	ms, err := fs.Glob(sys, "*")
	if err != nil {
		t.Fatalf("unexpected glob failure: %v", err)
	}
	if got, want := len(ms), 2; got != want {
		t.Fatalf("bad number of matches: got: %d, want: %d", got, want)
	}
	for _, n := range ms {
		if n == "." {
			continue // Expect the root.
		}
		if got, want := n, strings.Repeat("_", 100)+`bad\xfdname`; got != want {
			t.Fatalf("unexpected name: got: %q, want: %q", got, want)
		}
	}
}
