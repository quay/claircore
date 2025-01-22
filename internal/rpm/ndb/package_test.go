package ndb

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"iter"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/rpm/rpmdb"
)

func TestLoadPackage(t *testing.T) {
	ctx := context.Background()

	dir := os.DirFS("testdata")
	ms, err := fs.Glob(dir, "Packages*.db")
	if err != nil || len(ms) == 0 {
		t.Fatalf("error or not enough matches: %v/%d", err, len(ms))
	}
	for _, n := range ms {
		t.Run(n, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)

			blobs := blobSeq(t, ctx, dir, n)
			for blob := range blobs {
				var h rpmdb.Header
				if err := h.Parse(ctx, blob); err != nil {
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
		})
	}
}

func blobSeq(t testing.TB, ctx context.Context, sys fs.FS, name string) iter.Seq[io.ReaderAt] {
	t.Helper()

	b, err := fs.ReadFile(sys, name)
	if err != nil {
		t.Fatal(err)
	}

	var pkg PackageDB
	if err := pkg.Parse(bytes.NewReader(b)); err != nil {
		t.Fatal("error parsing Packages file", err)
	}
	seq, check := pkg.All(ctx)
	t.Cleanup(func() {
		if err := check(); err != nil {
			t.Error(err)
		}
	})

	return seq
}
