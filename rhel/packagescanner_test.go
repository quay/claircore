package rhel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/rpmtest"
)

//go:generate -command fetch go run github.com/quay/claircore/test/cmd/fetch-container-rpm-manifest
//go:generate fetch -o testdata/package/ubi8_ubi.txtar ubi8/ubi
//go:generate fetch -o testdata/package/ubi9_ubi.txtar ubi9/ubi
//go:generate fetch -o testdata/package/ubi9_httpd-24.txtar ubi9/httpd-24

func TestPackageDetection(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ms, err := filepath.Glob("testdata/package/*.txtar")
	if err != nil {
		panic("programmer error") // static glob
	}

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	// BUG(hank) The repoid information seems to not currently exist in Pyxis.
	// The tests here use a hard-coded allowlist.
	repoAllow := map[string][]string{
		"registry.access.redhat.com/ubi9/httpd-24": {"RHEL-9.0.0-updates-20220503.2-AppStream", "RHEL-9.0.0-updates-20220503.2-BaseOS"},
	}
	s := new(PackageScanner)

	for _, m := range ms {
		ar, err := rpmtest.OpenArchive(ctx, m)
		if err != nil {
			t.Error(err)
			continue
		}
		ar.Tests(ctx, a, repoAllow, s.Scan)(t)
	}
}
