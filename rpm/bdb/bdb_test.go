package bdb

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/rpm/internal/rpm"
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
			rds, err := pkg.AllHeaders(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("got %d headers", len(rds))
			for _, rd := range rds {
				var h rpm.Header
				if err := h.Parse(ctx, rd); err != nil {
					t.Fatal(err)
				}
				var found bool
				for i := range h.Infos {
					if h.Infos[i].Tag == rpm.TagName {
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
		})
	}
}
