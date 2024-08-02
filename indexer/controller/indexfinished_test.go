package controller

import (
	"context"
	"testing"

	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	indexer "github.com/quay/claircore/test/mock/indexer"
)

func TestIndexFinished(t *testing.T) {
	ctx := context.Background()
	tt := []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "Success",
			expectedState: Terminal,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)

				m.EXPECT().SetIndexFinished(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			store := table.mock(t)
			scnr := New(&indexer.Options{
				Store: store,
			})

			state, err := indexFinished(ctx, scnr)
			if err != nil {
				t.Error(err)
			}
			if got, want := state, table.expectedState; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
