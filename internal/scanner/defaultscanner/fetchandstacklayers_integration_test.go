//+build unix

package defaultscanner

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/defaultfetcher"
	"github.com/quay/claircore/test"
	"github.com/stretchr/testify/assert"
)

func Test_FetchAndStackLayers(t *testing.T) {
	// whether we delete the temporary directory where the layer was unpacked
	var PurgeTmpDirs = false
	var tt = []struct {
		// name of the test
		name string
		// name of the manifest to use
		hash string
		// number of layers to generate
		layers int
		// URIs to place into each layer.RemotePath.URI field. len(uris) must equal layers
		uris []string
	}{
		{

			name:   "integration",
			hash:   "test-manifest-hash",
			layers: 4,
			uris: []string{
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/74/7413c47ba209e555018c4be91101d017737f24b0c9d1f65339b97a4da98acb2a",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/0f/0fe7e7cbb2e88617d969efeeb3bd3125f7d309335c736a0525233ec2dc06aee1",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/1d/1d425c98234572d4221a1ac173162c4279f9fdde4726ec22ad3c399f59bb7503",
				"https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/34/344da5c95cecd0f55238ce59b8469ee301056001ece2b769e9691b80f94f9f37",
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := scanner.NewMockStore(ctrl)
			store.EXPECT().SetScanReport(gomock.Any()).Return(nil)

			// generate test manifest
			layers, err := test.GenUniqueLayersRemote(table.layers, table.uris)
			m := &claircore.Manifest{
				Hash:   table.hash,
				Layers: layers,
			}

			// generate scanner
			opts := &scanner.Opts{
				Store:   store,
				Fetcher: defaultfetcher.New(nil, nil, scanner.Tee),
			}
			if PurgeTmpDirs {
				opts.Fetcher.Purge()
			}

			s := New(opts)
			s.manifest = m

			_, err = fetchAndStackLayers(s, context.Background())
			assert.NoError(t, err)
		})
	}
}
