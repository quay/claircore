package test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore/test/integration"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// GenerateFunc is the user-supplied code to be used with [GenerateFixture].
type GenerateFunc func(testing.TB, context.Context, *os.File)

// GenerateFixture is a helper for generating a test fixture. A path that can be
// used to open the file is returned.
//
// If the test fails, the cached file is removed.
// It is the caller's responsibility to ensure that "name" is unique per-package.
func GenerateFixture(t testing.TB, ctx context.Context, name string, stamp time.Time, gen GenerateFunc) string {
	t.Helper()
	ctx, span := tracer.Start(ctx, "GenerateFixture")
	defer span.End()
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
	span.SetAttributes(attribute.String("cache.root", root), attribute.String("cache.dir", n))
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
		span.AddEvent("fixture up to date")
		t.Logf("generated file %q: up to date", n)
		span.SetStatus(codes.Ok, "")
		return p
	case err == nil && fi.ModTime().Before(stamp):
		span.AddEvent("fixture out of date")
	case errors.Is(err, os.ErrNotExist):
		span.AddEvent("fixture does not exist")
	default:
		span.SetStatus(codes.Error, "stat error")
		t.Fatalf("generated file %q: unexpected stat error: %v", n, err)
	}

	f, err := os.Create(p)
	if err != nil {
		span.SetStatus(codes.Error, "create error")
		t.Fatalf("generated file %q: unexpected create error: %v", n, err)
	}
	defer f.Close()

	ctx, span = tracer.Start(ctx, "GenerateFunc")
	gen(t, ctx, f)
	span.SetAttributes(attribute.Bool("failed", t.Failed()))
	span.End()
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
