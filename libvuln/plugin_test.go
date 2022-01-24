//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)
// +build linux,cgo darwin,cgo freebsd,cgo

package libvuln

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"
)

func TestPlugin(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			ms, err := fs.Glob(os.DirFS("testdata"), "*.so")
			if err != nil {
				t.Error(err)
				return
			}
			for _, m := range ms {
				os.Remove(m)
			}
		}
	})
	// `go test` doesn't use -trimpath to build the test binary, so make sure to
	// omit it here.
	cmd := exec.CommandContext(ctx, `go`, `build`, `-buildmode=plugin`, `-o`, filepath.Join(wd, `testdata/plugin.so`))
	if race {
		// This is needed because the race detector uses a different runtime
		// package.
		cmd.Args = append(cmd.Args, `-race`)
	}
	cmd.Dir = filepath.Join(wd, `driver/_plugin`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build plugin:\n%s", string(out))
	}
	t.Run("Matcher", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ms, err := loadMatchers(ctx, "testdata")
		if err != nil {
			t.Error(err)
		}
		if got, want := len(ms), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		for i, m := range ms {
			t.Logf("%d: %v", i, m.Name())
		}
	})
	t.Run("Enricher", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		es, err := loadEnrichers(ctx, "testdata")
		if err != nil {
			t.Error(err)
		}
		if got, want := len(es), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		for i, e := range es {
			t.Logf("%d: %v", i, e.Name())
		}
	})
	t.Run("Updater", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		usfs, err := loadUpdaters(ctx, "testdata")
		if err != nil {
			t.Error(err)
		}
		if got, want := len(usfs), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		for k, v := range usfs {
			t.Logf("%s:", k)
			s, err := v.UpdaterSet(ctx)
			if err != nil {
				t.Error(err)
				continue
			}
			for i, u := range s.Updaters() {
				t.Logf("%d: %v", i, u.Name())
			}
		}
	})
}
