package fetcher

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"

	"github.com/stretchr/testify/assert"
)

func Test_Fetcher_Integration(t *testing.T) {
	integration.Skip(t)
	var tt = []struct {
		// name of test
		name string
		// number of layers to generate
		layers int
		// uris to place into Layer.RemotePath.URI field for retrieval. len of this array must equal layers
		uris []string
		// how to fetch the layers
		layerFetchOpt scanner.LayerFetchOpt
	}{
		{
			name:   "ubuntu:latest uncompressed tar inmem fetch",
			layers: 4,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/74/7413c47ba209e555018c4be91101d017737f24b0c9d1f65339b97a4da98acb2a",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/0f/0fe7e7cbb2e88617d969efeeb3bd3125f7d309335c736a0525233ec2dc06aee1",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/1d/1d425c98234572d4221a1ac173162c4279f9fdde4726ec22ad3c399f59bb7503",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/34/344da5c95cecd0f55238ce59b8469ee301056001ece2b769e9691b80f94f9f37",
			},
			layerFetchOpt: scanner.InMem,
		},
	}

	for _, table := range tt {
		fetcher := New(nil, nil, table.layerFetchOpt)

		// gen layers
		layers, err := test.GenUniqueLayersRemote(table.layers, table.uris)
		if err != nil {
			t.Fatalf("failed to gen layers: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		err = fetcher.Fetch(ctx, layers)
		assert.NoError(t, err)

		if table.layerFetchOpt == scanner.InMem {
			for _, layer := range layers {
				assert.NotNil(t, layer.Bytes)
			}
		}

		if table.layerFetchOpt == scanner.OnDisk {
			for _, layer := range layers {
				assert.NotEmpty(t, layer.LocalPath)

				// assert file exists
				_, err := os.Stat(layer.LocalPath)
				if err != nil {
					t.Fatalf("failed to stat tmp file %v: %v", layer.LocalPath, err)
				}
			}

			// call purge and assert file is gone
			fetcher.Purge()

			for _, layer := range layers {
				_, err = os.Stat(layer.LocalPath)
				if err == nil {
					t.Fatalf("expected file %v to be removed after call to Purge", layer.LocalPath)
				}

				t.Log(layer.LocalPath)
			}
		}
	}
}
