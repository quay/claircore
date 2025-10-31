package controller

import (
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

// confirm checkManfest statefunc acts appropriately
// when manifest has been seen
func TestCheckManifest(t *testing.T) {
	tt := []struct {
		// the name of this test
		name string
		// the expected state returned
		expectedState State
		// a function to initialize any mocks
		mock func(t *testing.T) *indexer.MockStore
	}{
		{
			name:          "Seen",
			expectedState: Terminal,
			mock: func(t *testing.T) *indexer.MockStore {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)
				m.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
				m.EXPECT().IndexReport(gomock.Any(), gomock.Any()).Return(&claircore.IndexReport{}, true, nil)
				return m
			},
		},
		{
			name:          "Unseen",
			expectedState: FetchLayers,
			mock: func(t *testing.T) *indexer.MockStore {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)
				m.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
				m.EXPECT().PersistManifest(gomock.Any(), gomock.Any()).Return(nil)
				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := test.Logging(t)
			// get mock
			m := table.mock(t)

			// create indexer
			opts := &indexer.Options{
				Store: m,
			}
			s := New(opts)

			// call state func
			state, err := checkManifest(ctx, s)
			if err != nil {
				t.Error(err)
			}
			if got, want := state, table.expectedState; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
