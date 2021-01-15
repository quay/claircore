package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/indexer"
)

func TestIndexManifest(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
		err           bool
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "Success",
			expectedState: IndexFinished,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer.NewMockStore(ctrl)
				s.EXPECT().IndexManifest(gomock.Any(), gomock.Any()).Return(nil)
				return s
			},
		},
		{
			name:          "Failure",
			expectedState: Terminal,
			err:           true,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer.NewMockStore(ctrl)
				s.EXPECT().IndexManifest(gomock.Any(), gomock.Any()).Return(fmt.Errorf("failure"))
				return s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = zlog.Test(ctx, t)
			s := table.mock(t)
			indexer := New(&indexer.Opts{
				Store: s,
			})

			state, err := indexManifest(ctx, indexer)
			if (err == nil) == table.err {
				t.Fatalf("did not expect error: %v", err)
			}
			if table.expectedState != state {
				t.Fatalf("got: %v, want: %v", state, table.expectedState)
			}
		})
	}
}
