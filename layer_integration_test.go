// we will use the claircore_test package here to avoid import cycles when
// importing the fetcher.fetcher. using the fetcher is an attempt to not repeat
// a lot of layer fetching code. if this pattern continues reconsider importing anything
// into claircore package
package claircore_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

var goldenLayers []test.LayerSpec

func init() {
	id, err := claircore.ParseDigest("sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a")
	if err != nil {
		panic(err)
	}
	goldenLayers = []test.LayerSpec{
		{
			Domain: "docker.io",
			Repo:   "library/ubuntu",
			ID:     id,
		},
	}
}

func Test_Layer_Files_Miss(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// name of the test
		name string
		// the number of layers to generate for the test
		layers []test.LayerSpec
		// a list of paths we know exist in the retrieved layer(s). we wil test to make sure their associated
		// buffer is full
		paths []string
	}{
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			// fetch the layer
			ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			layers := test.RealizeLayers(ctx, t, table.layers...)

			// attempt to get files
			_, err := layers[0].Files(table.paths...)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func Test_Layer_Files_Hit(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// name of the test
		name string
		// the number of layers to generate for the test
		layers []test.LayerSpec
		// a list of paths we know exist in the retrieved layer(s). we wil test to make sure their associated
		// buffer is full
		paths []string
	}{
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			// fetch the layer
			ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
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
