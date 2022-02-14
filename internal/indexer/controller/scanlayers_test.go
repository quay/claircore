package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/zlog"

	indexer "github.com/quay/claircore/test/mock/indexer"
)

func TestScanLayers(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		mock          func(t *testing.T) (indexer.LayerScanner, indexer.Store)
		name          string
		expectedState State
	}{
		{
			name:          "Success",
			expectedState: Coalesce,
			mock: func(t *testing.T) (indexer.LayerScanner, indexer.Store) {
				ctrl := gomock.NewController(t)
				ls := indexer.NewMockLayerScanner(ctrl)
				s := indexer.NewMockStore(ctrl)

				ls.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1).MinTimes(1).Return(nil)
				s.EXPECT().LayerScanned(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(true, nil)
				return ls, s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = zlog.Test(ctx, t)
			ls, s := table.mock(t)
			scnr := New(&indexer.Opts{
				LayerScanner: ls,
				Store:        s,
			})

			state, err := scanLayers(ctx, scnr)
			if err != nil {
				t.Error(err)
			}
			if got, want := state, table.expectedState; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
