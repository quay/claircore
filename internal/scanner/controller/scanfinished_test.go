package controller

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func Test_ScanFinished_Success(t *testing.T) {
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) scanner.Store
	}{
		{
			name:          "successful scan finished",
			expectedState: Terminal,
			mock: func(t *testing.T) scanner.Store {
				ctrl := gomock.NewController(t)
				m := scanner.NewMockStore(ctrl)

				m.EXPECT().SetScanFinished(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				m.EXPECT().SetScanReport(gomock.Any(), gomock.Any()).Return(nil)

				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			store := table.mock(t)
			scnr := New(&scanner.Opts{
				Store: store,
			})

			state, err := scanFinished(context.Background(), scnr)

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
		})
	}
}
