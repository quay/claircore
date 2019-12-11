package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/internal/indexer"
)

func Test_IndexFinished_Success(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "successful index finished",
			expectedState: Terminal,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				m := indexer.NewMockStore(ctrl)

				m.EXPECT().SetIndexFinished(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				m.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			store := table.mock(t)
			scnr := New(&indexer.Opts{
				Store: store,
			})

			state, err := indexFinished(ctx, scnr)

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
