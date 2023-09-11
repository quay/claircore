package test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore/test/integration"
)

// GenerateFixture is a helper for generating a test fixture. A path that can be
// used to open the file is returned.
//
// If the test fails, the cached file is removed.
// It is the caller's responsibility to ensure that "name" is unique per-package.
func GenerateFixture(t testing.TB, name string, stamp time.Time, gen func(testing.TB, *os.File)) string {
	t.Helper()
	if !fs.ValidPath(name) || strings.Contains(name, "/") {
		t.Fatalf(`can't use "name" as a filename: %q`, name)
	}
	root := integration.CacheDir(t)
	// Generated fixtures are stored in the per-package cache.
	p := filepath.Join(integration.PackageCacheDir(t), name)
	// Nice name
	n, err := filepath.Rel(root, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("generated file %q: removing due to failed test", n)
			if err := os.Remove(p); err != nil {
				t.Errorf("generated file %q: unexpected remove error: %v", n, err)
			}
		}
	})
	fi, err := os.Stat(p)
	switch {
	case err == nil && !fi.ModTime().Before(stamp): // not before to get ">="
		t.Logf("generated file %q: up to date", n)
		return p
	case err == nil && fi.ModTime().Before(stamp):
	case errors.Is(err, os.ErrNotExist):
	default:
		t.Fatalf("generated file %q: unexpected stat error: %v", n, err)
	}

	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("generated file %q: unexpected create error: %v", n, err)
	}
	defer f.Close()

	gen(t, f)
	return p
}

// Modtime is a helper for picking a timestamp to use with [GenerateFixture] and
// [GenerateLayer].
//
// It reports the modtime of the passed path. If the file does not exist, the
// start of the UNIX epoch is returned. If the file is not regular or a
// directory, the test is failed. If the file is a directory, the newest time of
// all the entries is reported.
func Modtime(t testing.TB, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, os.ErrNotExist):
		return time.UnixMilli(0)
	default:
		t.Fatalf("modtime: unexpected stat error: %v", err)
	}
	switch m := fi.Mode(); {
	case m.IsRegular():
		return fi.ModTime()
	case m.IsDir(): // Fall out of switch
	default:
		t.Fatalf("modtime: unexpected file mode: %v", m)
	}

	// Called on dir, pick the latest time of all the children.
	// Do this the verbose way to avoid the sort incurred by [os.ReadDir].
	d, err := os.Open(path)
	if err != nil {
		t.Fatalf("modtime: unexpected open error: %v", err)
	}
	defer d.Close()
	ents, err := d.ReadDir(0)
	if err != nil {
		t.Fatalf("modtime: unexpected readdir error: %v", err)
	}
	stamp := time.UnixMilli(0)
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatalf("modtime: unexpected dirent stat error: %v", err)
		}
		if mt := fi.ModTime(); mt.After(stamp) {
			stamp = mt
		}
	}
	return stamp
}
