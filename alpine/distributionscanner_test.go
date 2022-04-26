package alpine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
)

type distTestcase struct {
	Release
	OSRelease string
	Issue     string
}

func TestDistributionScanner(t *testing.T) {
	table := []distTestcase{
		{
			Release:   V3_3,
			OSRelease: mustRead(t, `testdata/3.3/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.3/etc/issue`),
		},
		{
			Release:   V3_4,
			OSRelease: mustRead(t, `testdata/3.4/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.4/etc/issue`),
		},
		{
			Release:   V3_5,
			OSRelease: mustRead(t, `testdata/3.5/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.5/etc/issue`),
		},
		{
			Release:   V3_6,
			OSRelease: mustRead(t, `testdata/3.6/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.6/etc/issue`),
		},
		{
			Release:   V3_7,
			OSRelease: mustRead(t, `testdata/3.7/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.7/etc/issue`),
		},
		{
			Release:   V3_8,
			OSRelease: mustRead(t, `testdata/3.8/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.8/etc/issue`),
		},
		{
			Release:   V3_9,
			OSRelease: mustRead(t, `testdata/3.9/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.9/etc/issue`),
		},
		{
			Release:   V3_10,
			OSRelease: mustRead(t, `testdata/3.10/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.10/etc/issue`),
		},
		{
			Release:   V3_11,
			OSRelease: mustRead(t, `testdata/3.11/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.11/etc/issue`),
		},
		{
			Release:   V3_12,
			OSRelease: mustRead(t, `testdata/3.12/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.12/etc/issue`),
		},
		{
			Release:   V3_13,
			OSRelease: mustRead(t, `testdata/3.13/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.13/etc/issue`),
		},
		{
			Release:   V3_14,
			OSRelease: mustRead(t, `testdata/3.14/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.14/etc/issue`),
		},
		{
			Release:   V3_15,
			OSRelease: mustRead(t, `testdata/3.15/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.15/etc/issue`),
		},
		{
			Release:   V3_16,
			OSRelease: mustRead(t, `testdata/3.16/etc/os-release`),
			Issue:     mustRead(t, `testdata/3.16/etc/issue`),
		},
	}
	for _, tt := range table {
		t.Run(string(tt.Release), func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBufferString(tt.OSRelease))
			if got, want := dist, releaseToDist(tt.Release); !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
			dist = scanner.parse(bytes.NewBufferString(tt.Issue))
			if got, want := dist, releaseToDist(tt.Release); !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func mustRead(t *testing.T, p string) string {
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScanFs(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)

	td := os.DirFS("testdata")
	ms, err := fs.Glob(td, "3.*")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ms {
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
