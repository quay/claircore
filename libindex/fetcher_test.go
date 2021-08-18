package libindex

import (
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

type fetchTestcase struct {
	N int
}

func (tc fetchTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		c, layers := test.ServeLayers(t, tc.N)
		for _, l := range layers {
			t.Logf("%+v", l)
		}
		p, err := filepath.Abs("testdata")
		if err != nil {
			t.Error(err)
		}

		a := &FetchArena{}
		a.Init(c, p)

		fetcher := a.Fetcher()
		if err := fetcher.Fetch(ctx, layers); err != nil {
			t.Error(err)
		}
		for _, l := range layers {
			t.Logf("%+v", l)
		}
		if err := fetcher.Close(); err != nil {
			t.Error(err)
		}
	}
}

func TestFetchSimple(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []fetchTestcase{
		{N: 1},
		{N: 4},
		{N: 32},
	}

	for _, tc := range tt {
		t.Run(strconv.Itoa(tc.N), tc.Run(ctx))
	}
}

func TestFetchInvalid(t *testing.T) {
	// TODO(hank) Rewrite this into unified testcases.
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		name  string
		layer []*claircore.Layer
	}{
		{
			name: "no remote path or local path provided",
			layer: []*claircore.Layer{
				&claircore.Layer{
					URI: "",
				},
			},
		},
		{
			name: "path with no scheme",
			layer: []*claircore.Layer{
				&claircore.Layer{
					URI: "www.example.com/path/to/tar?query=one",
				},
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			p, err := filepath.Abs("testdata")
			if err != nil {
				t.Error(err)
			}
			a := &FetchArena{}
			a.Init(http.DefaultClient, p)

			fetcher := a.Fetcher()
			if err := fetcher.Fetch(ctx, table.layer); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
