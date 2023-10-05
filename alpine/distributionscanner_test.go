package alpine

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestScanFs(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)

	td := os.DirFS("testdata")
	ms, err := fs.Glob(td, "3.*")
	if err != nil {
		t.Fatal(err)
	}
	edge, err := fs.Glob(td, "edge")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range append(ms, edge...) {
		sub, err := fs.Sub(td, v)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(v, scanFsTestcase(ctx, sub))
	}
}

func scanFsTestcase(ctx context.Context, sys fs.FS) func(*testing.T) {
	var s DistributionScanner
	var want []*claircore.Distribution
	in, err := fs.ReadFile(sys, "want")
	if err == nil {
		err = json.Unmarshal(in, &want)
	}
	return func(t *testing.T) {
		if err != nil {
			t.Fatal(err)
		}
		ctx := zlog.Test(ctx, t)
		got, err := s.scanFs(ctx, sys)
		if err != nil {
			t.Error(err)
		}
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
