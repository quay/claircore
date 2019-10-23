// we will use the claircore_test package here to avoid import cycles when
// importing the fetcher.fetcher. using the fetcher is an attempt to not repeat
// a lot of layer fetching code. if this pattern continues reconsider importing anything
// into claircore package
package claircore_test

import (
	"context"
	"testing"
	"time"

	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/fetcher"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"

	"github.com/stretchr/testify/assert"
)

func Test_Layer_Files_Miss(t *testing.T) {
	integration.Skip(t)
	var tt = []struct {
		// name of the test
		name string
		// use a fetcher to retrieve the layer contents.
		// we assume the Fetcher implementation unit and integration
		// tests are passing. if an issue appears to be from the fetcher
		// confirm the implementation's tests are passing
		fetcher scanner.Fetcher
		// the number of layers to generate for the test
		layers int
		// the uris to populate the layer.RemotePath.URI fields. len of this array must equal layers
		uris []string
		// a list of paths we know exist in the retrieved layer(s). we wil test to make sure their associated
		// buffer is full
		paths []string
	}{
		{
			name:    "ubuntu:18.04 fake path, leading slash, inmem fetch",
			fetcher: fetcher.New(nil, nil, scanner.InMem),
			layers:  1,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/35/35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
			},
			paths: []string{"/path/to/nowhere"},
		},
		{
			name:    "ubuntu:18.04 fake path, no leading slash, inmem fetch",
			fetcher: fetcher.New(nil, nil, scanner.InMem),
			layers:  1,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/35/35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
			},
			paths: []string{"path/to/nowhere"},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			// gen layers
			layers, err := test.GenUniqueLayersRemote(table.layers, table.uris)

			// fetch the layer
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			err = table.fetcher.Fetch(ctx, layers)
			assert.NoError(t, err, "fetcher returned an error")

			// attempt to get files
			files, err := layers[0].Files(table.paths)
			assert.NoError(t, err, "Files method returned an error")

			// confirm byte array is not empty
			for _, path := range table.paths {
				var b []byte
				var ok bool
				if b, ok = files[path]; !ok {
					t.Fatalf("test path %v was not found in resulting file map", path)
				}
				if len(b) > 0 {
					t.Fatalf("returned buffer for path %v has len %v", path, len(b))
				}

				t.Logf("File:\n%v\n", string(b))
			}
		})
	}
}

func Test_Layer_Files_Hit(t *testing.T) {
	integration.Skip(t)
	var tt = []struct {
		// name of the test
		name string
		// use a fetcher to retrieve the layer contents.
		// we assume the Fetcher implementation unit and integration
		// tests are passing. if an issue appears to be from the fetcher
		// confirm the implementation's tests are passing
		fetcher scanner.Fetcher
		// the number of layers to generate for the test
		layers int
		// the uris to populate the layer.RemotePath.URI fields. len of this array must equal layers
		uris []string
		// a list of paths we know exist in the retrieved layer(s). we wil test to make sure their associated
		// buffer is full
		paths []string
	}{
		{
			name:    "ubuntu:18.04 os-release (linked file), leading slash, inmem fetch",
			fetcher: fetcher.New(nil, nil, scanner.InMem),
			layers:  1,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/35/35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
			},
			paths: []string{"/etc/os-release"},
		},
		{
			name:    "ubuntu:18.04 os-release (linked file), no leading slash, inmem fetch",
			fetcher: fetcher.New(nil, nil, scanner.InMem),
			layers:  1,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/35/35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
			},
			paths: []string{"etc/os-release"},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			// gen layers
			layers, err := test.GenUniqueLayersRemote(table.layers, table.uris)

			// fetch the layer
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			err = table.fetcher.Fetch(ctx, layers)
			assert.NoError(t, err, "fetcher returned an error")

			// attempt to get files
			files, err := layers[0].Files(table.paths)
			assert.NoError(t, err, "Files method returned an error")

			// confirm byte array is not empty
			for _, path := range table.paths {
				var b []byte
				var ok bool
				if b, ok = files[path]; !ok {
					t.Fatalf("test path %v was not found in resulting file map", path)
				}
				if len(b) <= 0 {
					t.Fatalf("returned buffer for path %v has len %v", path, len(b))
				}

				t.Logf("File:\n%v\n", string(b))
			}
		})
	}
}
