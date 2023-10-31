package tarfs_test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
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
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/zlog"

	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/test"
)

var (
	// ModTime reports the newest modtime for files in the current directory.
	//
	// TODO(hank) Replace this with [sync.OnceValue] in go1.21.
	modTime time.Time
)

func init() {
	dent, err := os.ReadDir(".")
	if err != nil {
		panic(err)
	}
	var r time.Time
	for _, d := range dent {
		fi, err := d.Info()
		if err != nil {
			panic(err)
		}
		m := fi.ModTime()
		if m.After(r) {
			r = m
		}
	}
	modTime = r
}

// TestFS runs some sanity checks on a tar generated from this package's
// directory.
//
// The tar is generated on demand and removed if tests fail, so modifying any
// file in this package will cause tests slow down on the next run.
func TestFS(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	t.Parallel()
	name := test.GenerateFixture(t, `fstest.tar`, modTime, makeFixture(""))
	test.GenerateFixture(t, `fstest.tar.gz`, modTime, makeFixture("gz"))
	test.GenerateFixture(t, `fstest.tar.zstd`, modTime, makeFixture("zstd"))
	fileset := []string{
		"file.go",
		"fs.go",
		"metrics.go",
		"parse.go",
		"pool.go",
		"randomaccess.go",
		"seekable_test.go",
		"srv.go",
		"tarfs.go",
		"tarfs_test.go",
		"testdata/atroot",
	}

	mkBuf := func(t *testing.T) *os.File {
		t.Helper()
		f, err := os.Create(filepath.Join(t.TempDir(), "buffer"))
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		return f
	}
	openFile := func(name string) func(*testing.T) *os.File {
		return func(t *testing.T) *os.File {
			t.Helper()
			f, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			})
			return f
		}
	}

	tt := []fsTestcase{
		{
			Name: "Single",
			Check: func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T) {
				return func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					f := open(t)
					sys, err := tarfs.New(ctx, f, -1, mkBuf(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sys.Close()

					if err := fstest.TestFS(sys, fileset...); err != nil {
						t.Error(err)
					}
				}
			},
		},
		{
			Name: "NotAFile",
			Check: func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T) {
				return func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					f := open(t)
					b, err := io.ReadAll(f)
					if err != nil {
						t.Error(err)
					}
					rd := bytes.NewReader(b)
					sys, err := tarfs.New(ctx, rd, -1, mkBuf(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sys.Close()

					if err := fstest.TestFS(sys, fileset...); err != nil {
						t.Error(err)
					}
				}
			},
		},
		{
			Name: "Concurrent",
			Check: func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T) {
				return func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					f := open(t)
					fi, err := f.Stat()
					if err != nil {
						t.Fatal(err)
					}
					sys, err := tarfs.New(ctx, f, fi.Size(), mkBuf(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sys.Close()

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
				}
			},
		},
		{
			Name: "Sub",
			Check: func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T) {
				return func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					f := open(t)
					sys, err := tarfs.New(ctx, f, -1, mkBuf(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sys.Close()

					sub, err := fs.Sub(sys, "testdata")
					if err != nil {
						t.Error(err)
					}
					if err := fstest.TestFS(sub, "atroot"); err != nil {
						t.Error(err)
					}
				}
			},
		},
		{
			Name: "Checksum",
			Check: func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T) {
				return func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					f := open(t)
					sys, err := tarfs.New(ctx, f, -1, mkBuf(t))
					if err != nil {
						t.Fatal(err)
					}
					defer sys.Close()
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
				}
			},
		},
	}

	t.Run("Uncompressed", func(t *testing.T) {
		t.Parallel()
		bufHack := func(t *testing.T) *os.File {
			t.Helper()
			if path.Base(t.Name()) != "NotAFile" {
				return nil
			}
			return mkBuf(t)
		}
		for _, tc := range tt {
			t.Run(tc.Name, tc.Check(ctx, openFile(name), bufHack))
		}
	})
	t.Run("Gzip", func(t *testing.T) {
		t.Parallel()
		for _, tc := range tt {
			t.Run(tc.Name, tc.Check(ctx, openFile(name+".gz"), mkBuf))
		}
	})
	t.Run("Zstd", func(t *testing.T) {
		t.Parallel()
		for _, tc := range tt {
			t.Run(tc.Name, tc.Check(ctx, openFile(name+".zstd"), mkBuf))
		}
	})
}

type fsTestcase struct {
	Check func(ctx context.Context, open, mkBuf func(*testing.T) *os.File) func(*testing.T)
	Name  string
}

// MakeFixture makes the expected tar for TestFS, with the compression "cmp".
//
// "Cmp" must be one of:
//   - ""
//   - gz
//   - zstd
func makeFixture(cmp string) func(testing.TB, *os.File) {
	return func(t testing.TB, f *os.File) {
		var w io.Writer
		buf := bufio.NewWriter(f)
		defer func() {
			if err := buf.Flush(); err != nil {
				t.Error(err)
			}
		}()
		switch cmp {
		case "":
			w = buf
		case "gz":
			z := gzip.NewWriter(buf)
			defer z.Close()
			w = z
		case "zstd":
			z, err := zstd.NewWriter(buf)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			w = z
		default:
			t.Fatalf("unknown compression scheme: %q", cmp)
		}

		tw := tar.NewWriter(w)
		defer tw.Close()
		in := os.DirFS(".")
		if err := fs.WalkDir(in, ".", mktar(t, filepath.Base(f.Name()), in, tw)); err != nil {
			t.Fatal(err)
		}
	}
}

// Mktar is a [fs.WalkDirFunc] to copy files from "in" to "tw".
//
// "Name" is supplied for logging only.
func mktar(t testing.TB, name string, in fs.FS, tw *tar.Writer) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch ext := path.Ext(d.Name()); {
		case ext == ".tar" || ext == ".gz" || ext == ".zstd":
			// Skip all these.
			return nil
		case d.Name() == "." && d.IsDir():
			return nil
		case d.Name() == "known" && d.IsDir():
			return fs.SkipDir
		default:
		}
		t.Logf("%s: adding %q", name, p)
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

// TestEmpty tests that a wholly empty tar still creates an empty root.
func TestEmpty(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	f, err := os.Create(filepath.Join(t.TempDir(), filepath.Base(t.Name())))
	if err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	// Two zero blocks is the tar footer, so just make one up.
	if err := f.Truncate(2 * 512); err != nil {
		t.Error(err)
	}
	sys, err := tarfs.New(ctx, f, -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Close()
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

func TestSymlinks(t *testing.T) {
	t.Parallel()
	run := func(openErr bool, hs []tar.Header, chk func(*testing.T, fs.FS)) func(*testing.T) {
		return func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			t.Helper()
			name := test.GenerateFixture(t, path.Base(t.Name())+".tar", modTime, func(t testing.TB, f *os.File) {
				tw := tar.NewWriter(f)
				for i := range hs {
					if err := tw.WriteHeader(&hs[i]); err != nil {
						t.Error(err)
					}
				}
				if err := tw.Close(); err != nil {
					t.Error(err)
				}
			})
			f, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			fi, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}

			sys, err := tarfs.New(ctx, f, fi.Size(), nil)
			t.Log(err)
			t.Cleanup(func() {
				if sys != nil {
					if err := sys.Close(); err != nil {
						t.Error(err)
					}
				}
			})
			if (err != nil) != openErr {
				t.FailNow()
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
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
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
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(filepath.Join(`testdata/known`, n))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sys, err := tarfs.New(ctx, f, -1, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer sys.Close()
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
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
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
		sys, err := tarfs.New(ctx, f, -1, nil)
		if err != nil {
			t.Fatalf("failed to create tarfs: %v", err)
		}
		defer sys.Close()
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
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	f, err := os.Open(`testdata/bad_name.tar`)
	if err != nil {
		t.Fatalf("failed to open test tar: %v", err)
	}
	defer f.Close()
	sys, err := tarfs.New(ctx, f, -1, nil)
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
