package defaultlayerscanner

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

// Test_Deferred_Work confirms our layer scanner will
// only attempt to fetch the same layer once and calls the
// store methods the appropriate number of times
func Test_Deferred_Work(t *testing.T) {

	mock := func(t *testing.T, scnrsN int, layersN int) (scanner.Store, scanner.Fetcher, []scanner.PackageScanner) {
		ctrl := gomock.NewController(t)
		store := scanner.NewMockStore(ctrl)
		fetcher := scanner.NewMockFetcher(ctrl)
		scnrs := []scanner.PackageScanner{}

		for i := 0; i < scnrsN; i++ {
			scnr := scanner.NewMockPackageScanner(ctrl)
			scnr.EXPECT().Name().AnyTimes().Return("")
			scnr.EXPECT().Kind().AnyTimes().Return("")
			scnr.EXPECT().Version().AnyTimes().Return("")
			// we should expect Scan to be called the number of layers provided * 2. One time
			// for the invidiaul layer scan and another for the image layer scan
			scnr.EXPECT().Scan(gomock.Any()).MaxTimes(layersN * 2)
			scnrs = append(scnrs, scnr)
		}

		// these should be scnrsN * layersN  queries or in other words, for each scnr
		// ask if each layer has been scanned in cases where no work can be deferred (LayerScanned returns false)
		store.EXPECT().LayerScanned(gomock.Any(), gomock.Any()).MaxTimes(layersN*scnrsN).MinTimes(layersN*scnrsN).Return(false, nil)
		store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(layersN * scnrsN).MinTimes(layersN * scnrsN).Return(nil)

		// we should only call Fetch to retrive a layer once per layer
		fetcher.EXPECT().Fetch(gomock.Any(), gomock.Any()).MaxTimes(layersN).MinTimes(layersN).Return(nil)

		return store, fetcher, scnrs
	}

	var tt = []struct {
		// the name of the test
		name string
		// the layers to be scanned
		layers []*claircore.Layer
		// the concurrency level of the scanner
		cLevel int
		// number of scnr mocks to create
		scnrs int
	}{
		{
			name:   "one layer, one package scanners",
			cLevel: 1,
			layers: []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-hash-1",
				},
			},
			scnrs: 1,
		},
		{
			name:   "one layer, two package scanners",
			cLevel: 2,
			layers: []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-hash-1",
				},
			},
			scnrs: 2,
		},
		{
			name:   "two layers, two package scanners",
			cLevel: 2,
			layers: []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-hash-1",
				},
				&claircore.Layer{
					Hash: "test-layer-hash-2",
				},
			},
			scnrs: 2,
		},
		{
			name:   "two layers, four package scanners",
			cLevel: 2,
			layers: []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-hash-1",
				},
				&claircore.Layer{
					Hash: "test-layer-hash-2",
				},
			},
			scnrs: 4,
		},
		{
			name:   "four layers, four package scanners",
			cLevel: 2,
			layers: []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-hash-1",
				},
				&claircore.Layer{
					Hash: "test-layer-hash-2",
				},
				&claircore.Layer{
					Hash: "test-layer-hash-3",
				},
				&claircore.Layer{
					Hash: "test-layer-hash-4",
				},
			},
			scnrs: 4,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			store, fetcher, scnrs := mock(t, table.scnrs, len(table.layers))
			ls := New(table.cLevel, &scanner.Opts{
				Store:           store,
				Fetcher:         fetcher,
				PackageScanners: scnrs,
			})

			err := ls.Scan(context.Background(), "test-manifest", table.layers)
			assert.NoError(t, err)
		})
	}
}
