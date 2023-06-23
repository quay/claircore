// Package integration is a helper for running integration tests.
package integration

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Skip will skip the current test or benchmark if this package was built without
// the "integration" build tag unless the "CI" environment variable is defined
// and the "short" flag is not provided.
//
// This should be used as an annotation at the top of the function, like
// (*testing.T).Parallel().
//
// See the example for usage.
func Skip(t testing.TB) {
	switch {
	case testing.Short():
		t.Skip(`skipping integration test: short tests`)
	case inCI && skip:
		t.Log(`enabling integration test: environment variable "CI" is defined`)
	case skip:
		t.Skip("skipping integration test: integration tag not provided")
	}
}

var inCI, inGHA bool

func init() {
	inCI, _ = strconv.ParseBool(os.Getenv("CI"))
	inGHA, _ = strconv.ParseBool(os.Getenv("GITHUB_ACTIONS"))
}

// CacheDir reports a directory for caching test data and creates it if
// necessary.
func CacheDir(t testing.TB) string {
	cacheOnce.Do(func() {
		d, err := os.UserCacheDir()
		if err != nil {
			t.Fatalf("unable to determine test cache dir: %v", err)
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("unable to create test cache dir: %v", err)
		}
		d = filepath.Join(d, `clair-testing`)
		switch err := os.Mkdir(d, 0o755); {
		case errors.Is(err, nil): // Make cachedir tag
			p := filepath.Join(d, `CACHEDIR.TAG`)
			f, err := os.Create(p)
			if err != nil {
				// If we can't create this file, we're going to have a hell of a
				// time creating other ones.
				t.Fatalf("tried to create %q but failed: %v", p, err)
			}
			defer f.Close()
			if _, err := io.WriteString(f, cachedirtag); err != nil {
				t.Logf("error writing %q contents: %v", p, err)
			}
		case errors.Is(err, os.ErrExist): // Pre-existing
		default:
			t.Fatalf("unable to create test cache dir: %v", err)
		}
		cacheDir = d
	})
	if cacheDir == "" {
		t.Fatal("test cache dir error, check previous tests")
	}
	return cacheDir
}

var (
	cacheOnce sync.Once
	cacheDir  string
)

const cachedirtag = `Signature: 8a477f597d28d172789f06886806bc55
# This file is a cache directory tag created for "github.com/quay/claircore" test data.
# For information about cache directory tags, see:
#	http://www.brynosaurus.com/cachedir/
`

// PackageCacheDir reports a directory for caching per-package test data and
// creates it if necessary.
func PackageCacheDir(t testing.TB) string {
	pkgCacheOnce.Do(func() {
		ctx := context.Background()
		done := func() {}
		if d, ok := t.(deadliner); ok {
			if dl, ok := d.Deadline(); ok {
				ctx, done = context.WithDeadline(ctx, dl)
			}
			// If the above is false, then the test explicitly asked for no
			// timeout.
		} else {
			// Absurdly high timeout. Even higher than the previous 5 seconds.
			ctx, done = context.WithTimeout(ctx, 60*time.Second)
		}
		defer done()
		// This exec'ing is needed be cause test binaries are not built with
		// full debug.BuildInfo filled out.
		out, err := exec.CommandContext(ctx, `go`, `list`, `-m`).Output()
		if err != nil {
			if exit := new(exec.ExitError); errors.As(err, &exit) {
				t.Logf("exit code: %d", exit.ExitCode())
				t.Logf("stderr:\n%s", string(exit.Stderr))
			}
			t.Fatal(err)
		}
		skip := len(out) - 1
		out, err = exec.CommandContext(ctx, `go`, `list`, `.`).Output()
		if err != nil {
			if exit := new(exec.ExitError); errors.As(err, &exit) {
				t.Logf("exit code: %d", exit.ExitCode())
				t.Logf("stderr:\n%s", string(exit.Stderr))
			}
			t.Fatal(err)
		}
		// Swap separators, except for the one at the module/package boundary.
		for i, b := range out {
			if b == '/' && i != skip {
				out[i] = '_'
			}
		}
		// Join the resulting path (with the newline chomped) with the cache
		// root.
		d := CacheDir(t)
		d = filepath.Join(d, string(out[:len(out)-1]))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("unable to create per-package test cache dir %q: %v", d, err)
		}
		pkgCacheDir = d
	})
	if pkgCacheDir == "" {
		t.Fatal("test cache dir error, check previous tests")
	}
	return pkgCacheDir
}

// Deadliner is implemented by [testing.T] to report the test deadline.
type deadliner interface {
	Deadline() (deadline time.Time, ok bool)
}

var pkgCacheOnce sync.Once
var pkgCacheDir string
