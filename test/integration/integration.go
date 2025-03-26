// Package integration is a helper for running integration tests.
package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore/test/internal/cache"
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
	case inCI && integrationTag:
		t.Log(`enabling integration test: environment variable "CI" is defined`)
	case integrationTag:
		t.Skip("skipping integration test: integration tag not provided")
	}
}

// Skip is an internal variant of [Skip] that reports the decision and
// doesn't log.
//
// Because this calls [testing.Short], it cannot be used in the [package block]
// or an init function.
//
// [package block]: https://go.dev/ref/spec#Declarations_and_scope
func skip() bool {
	return testing.Short() || integrationTag && !inCI
}

var inCI, inGHA, externalDB bool

func init() {
	_, inCI = os.LookupEnv("CI")
	_, inGHA = os.LookupEnv("GITHUB_ACTIONS")
	_, externalDB = os.LookupEnv(EnvPGConnString)
	_, actuallyAct := os.LookupEnv("ACT")

	inGHA = inGHA && !actuallyAct
}

// CacheDir reports a directory for caching test data and creates it if
// necessary.
func CacheDir(t testing.TB) string {
	cacheOnce.Do(func() {
		var err error
		cacheDir, err = cache.CheckedDirectory()
		if err != nil {
			t.Fatal(err)
		}
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
		pkgCacheDir, err = cache.CheckedDirectory(string(out[:len(out)-1]))
		if err != nil {
			t.Fatal(err)
		}
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

var (
	pkgCacheOnce sync.Once
	pkgCacheDir  string
)
