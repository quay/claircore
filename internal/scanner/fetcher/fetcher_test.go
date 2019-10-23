package fetcher

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func Test_Fetcher_LocalPath(t *testing.T) {
	var tt = []struct {
		name  string
		layer []*claircore.Layer
	}{
		{
			name: "prexisting local path",
			layer: []*claircore.Layer{
				&claircore.Layer{
					LocalPath: "/tmp/path/to/tar/tar.gz",
					RemotePath: claircore.RemotePath{
						URI: "http://example-path.com/some/path?query=one",
					},
				},
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			fetcher := New(nil, nil, scanner.InMem)
			err := fetcher.Fetch(context.Background(), table.layer)

			assert.NoError(t, err)
		})
	}
}

func Test_Fetcher_InvalidPath(t *testing.T) {
	var tt = []struct {
		name  string
		layer []*claircore.Layer
	}{
		{
			name: "no remote path or local path provided",
			layer: []*claircore.Layer{
				&claircore.Layer{
					RemotePath: claircore.RemotePath{
						URI: "",
					},
					LocalPath: "",
				},
			},
		},
		{
			name: "path with no scheme",
			layer: []*claircore.Layer{
				&claircore.Layer{
					RemotePath: claircore.RemotePath{
						URI: "www.example.com/path/to/tar?query=one",
					},
					LocalPath: "",
				},
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			fetcher := New(nil, nil, scanner.InMem)
			err := fetcher.Fetch(context.Background(), table.layer)

			assert.Error(t, err)
		})
	}
}
