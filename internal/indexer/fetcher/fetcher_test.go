package fetcher

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/log"
)

// Custom TestMain to hook the TMPDIR environment variable.
func TestMain(m *testing.M) {
	p, err := filepath.Abs("testdata")
	if err != nil {
		panic(err)
	}
	os.Setenv("TMPDIR", p)
	// call flag.Parse() here if TestMain uses flags
	os.Exit(m.Run())
}

var testClient = http.Client{
	Timeout: 5 * time.Second,
}

type testcase struct {
	N int
}

func (tc testcase) Run(ctx context.Context) func(*testing.T) {
	ctx, done := context.WithCancel(ctx)
	return func(t *testing.T) {
		defer done()
		ctx = log.TestLogger(ctx, t)
		layers := test.ServeLayers(ctx, t, tc.N)
		for _, l := range layers {
			t.Logf("%+v", l)
		}

		fetcher := New(&testClient, indexer.LayerFetchOpt(""))
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

func TestSimple(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []testcase{
		{N: 1},
		{N: 4},
		{N: 32},
	}

	for _, tc := range tt {
		t.Run(strconv.Itoa(tc.N), tc.Run(ctx))
	}
}

func TestInvalid(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			fetcher := New(&testClient, indexer.InMem)
			if err := fetcher.Fetch(ctx, table.layer); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
