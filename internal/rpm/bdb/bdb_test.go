package bdb

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/rpm/rpmdb"
)

func TestLoadPackage(t *testing.T) {
	ctx := context.Background()

	dir := os.DirFS("testdata")
	ms, err := fs.Glob(dir, "*Packages")
	if err != nil || len(ms) == 0 {
		t.Fatalf("error or not enough matches: %v/%d", err, len(ms))
	}
	for _, n := range ms {
		t.Run(n, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			b, err := fs.ReadFile(dir, n)
			if err != nil {
				t.Fatal(err)
			}
			pkgf := bytes.NewReader(b)
			var pkg PackageDB
			if err := pkg.Parse(pkgf); err != nil {
				t.Fatal(err)
			}

			ct := 0
			seq, check := pkg.All(ctx)
			defer func() {
				if err := check(); err != nil {
					t.Error(err)
				}
			}()
			for rd := range seq {
				ct++

				var h rpmdb.Header
				if err := h.Parse(ctx, rd); err != nil {
					t.Fatal(err)
				}
				var found bool
				for i := range h.Infos {
					if h.Infos[i].Tag == rpmdb.TagName {
						v, err := h.ReadData(ctx, &h.Infos[i])
						if err != nil {
							t.Error(err)
							continue
						}
						t.Logf("package: %q", v)
						found = true
						break
					}
				}
				if !found {
					t.Error(`missing "name" tag`)
				}
			}
			t.Logf("got %d headers", ct)
		})
	}
}
