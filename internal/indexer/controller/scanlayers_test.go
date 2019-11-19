package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore/internal/indexer"
	"github.com/stretchr/testify/assert"
)

func Test_ScanLayers(t *testing.T) {
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) (indexer.LayerScanner, indexer.Store)
	}{
		{
			name:          "successful scan",
			expectedState: Coalesce,
			mock: func(t *testing.T) (indexer.LayerScanner, indexer.Store) {
				ctrl := gomock.NewController(t)
				ls := indexer.NewMockLayerScanner(ctrl)
				s := indexer.NewMockStore(ctrl)

				// called twice, once for individual layer scans and again for the image layer
				ls.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(2).MinTimes(2).Return(nil)
				s.EXPECT().SetScanReport(gomock.Any(), gomock.Any()).Return(nil)
				return ls, s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ls, s := table.mock(t)
			scnr := New(&indexer.Opts{
				LayerScanner: ls,
				Store:        s,
			})

			state, err := scanLayers(context.Background(), scnr)
			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
