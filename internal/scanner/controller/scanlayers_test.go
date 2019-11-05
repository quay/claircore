package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func Test_ScanLayers(t *testing.T) {
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) (scanner.LayerScanner, scanner.Store)
	}{
		{
			name:          "successful scan",
			expectedState: Coalesce,
			mock: func(t *testing.T) (scanner.LayerScanner, scanner.Store) {
				ctrl := gomock.NewController(t)
				ls := scanner.NewMockLayerScanner(ctrl)
				s := scanner.NewMockStore(ctrl)

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
			scnr := New(&scanner.Opts{
				LayerScanner: ls,
				Store:        s,
			})

			state, err := scanLayers(context.Background(), scnr)
			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
