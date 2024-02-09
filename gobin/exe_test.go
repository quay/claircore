package gobin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestBin(t *testing.T) {
	ms, err := filepath.Glob("testdata/bin/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range ms {
		name := filepath.Base(n)
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			f, err := os.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var out []*claircore.Package
			if err := toPackages(ctx, &out, name, f); err != nil {
				t.Fatal(err)
			}
			for _, pkg := range out {
				t.Logf("%s@%s / %v", pkg.Name, pkg.Version, pkg.NormalizedVersion.String())
			}
		})
	}
}
