package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// confirm checkManfest statefunc acts appropriately
// when manifest has been seen
func Test_CheckManifest_Seen(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of this test
		name string
		// the expected state returned
		expectedState State
		// a function to initialize any mocks
		mock func(t *testing.T) *indexer.MockStore
	}{
		{
			name:          "manifest seen",
			expectedState: Terminal,
			mock: func(t *testing.T) *indexer.MockStore {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)
				m.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)
				m.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
				m.EXPECT().IndexReport(gomock.Any(), gomock.Any()).Return(&claircore.IndexReport{}, true, nil)
				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			// get mock
			m := table.mock(t)

			// create indexer
			opts := &indexer.Opts{
				Store: m,
			}
			s := New(opts)

			// call state func
			state, err := checkManifest(ctx, s)

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}

// confirm checkManfest statefunc acts appropriately
// when manifest has been not been seen
func Test_CheckManifest_UnSeen(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of this test
		name string
		// the expected state of the indexer
		expectedState State
		// a function to initialize any mocks
		mock func(t *testing.T) *indexer.MockStore
	}{
		{
			name:          "manifest seen",
			expectedState: FetchLayers,
			mock: func(t *testing.T) *indexer.MockStore {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)
				m.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)
				m.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
				m.EXPECT().IndexReport(gomock.Any(), gomock.Any()).Return(&claircore.IndexReport{}, true, nil)
				m.EXPECT().PersistManifest(gomock.Any(), gomock.Any()).Return(nil)
				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			// get mock
			m := table.mock(t)

			// create indexer
			opts := &indexer.Opts{
				Store: m,
			}
			s := New(opts)

			// call state func
			state, err := checkManifest(ctx, s)

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
