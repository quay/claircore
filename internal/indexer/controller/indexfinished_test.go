package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/internal/indexer"
)

func Test_ScanFinished_Success(t *testing.T) {
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "successful scan finished",
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
			store := table.mock(t)
			scnr := New(&indexer.Opts{
				Store: store,
			})

			state, err := indexFinished(context.Background(), scnr)

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
