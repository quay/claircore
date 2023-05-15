package tarfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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
	run := func(wantErr bool, hs []tar.Header, chk func(*testing.T, fs.FS)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
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
			if (err != nil) != wantErr {
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
