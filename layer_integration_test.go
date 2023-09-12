package claircore_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

// TODO(hank) These tests should be OK to remove, as the tarfs code now
// encapsulates a better way to do this and exercises that in its tests.

var goldenLayers = []test.LayerRef{
	{
		Registry: "docker.io",
		Name:     "library/ubuntu",
		Digest:   "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
	},
}

type filesTestcase struct {
	name   string
	layers []test.LayerRef
	// A list of paths we know exist in the retrieved layer(s).
	// We will test to make sure their associated buffer is full.
	paths []string
}

func TestLayerFilesMiss(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []filesTestcase{
		{
			name:   "ubuntu:18.04 fake path, leading slash",
			layers: goldenLayers,
			paths:  []string{"/path/to/nowhere"},
		},
		{
			name:   "ubuntu:18.04 fake path, no leading slash",
			layers: goldenLayers,
			paths:  []string{"path/to/nowhere"},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			// fetch the layer
			layers := test.RealizeLayers(ctx, t, table.layers...)

			// attempt to get files
			_, err := layers[0].Files(table.paths...)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestLayerFilesHit(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []filesTestcase{
		{
			name:   "ubuntu:18.04 os-release (linked file), leading slash, inmem fetch",
			layers: goldenLayers,
			paths:  []string{"/etc/os-release"},
		},
		{
			name:   "ubuntu:18.04 os-release (linked file), no leading slash, inmem fetch",
			layers: goldenLayers,
			paths:  []string{"etc/os-release"},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			// fetch the layer
			layers := test.RealizeLayers(ctx, t, table.layers...)

			// attempt to get files
			files, err := layers[0].Files(table.paths...)
			if err != nil {
				t.Fatal(err)
			}

			var b *bytes.Buffer
			var ok bool
			for _, path := range table.paths {
				if b, ok = files[path]; !ok {
					t.Fatalf("test path %v was not found in resulting file map", path)
				}
				if l := b.Len(); l <= 0 {
					t.Fatalf("returned buffer for path %v has len %v", path, l)
				}

				t.Logf("contents: %+q", b.String())
			}
		})
	}
}
