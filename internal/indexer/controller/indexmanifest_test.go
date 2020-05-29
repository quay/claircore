package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore/internal/indexer"
)

func Test_IndexManifest(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "successful index",
			expectedState: IndexFinished,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer.NewMockStore(ctrl)
				s.EXPECT().IndexManifest(gomock.Any(), gomock.Any()).Return(nil)
				return s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			s := table.mock(t)
			indexer := New(&indexer.Opts{
				Store: s,
			})

			state, err := indexManifest(ctx, indexer)
			if err != nil {
				t.Fatalf("did not expect error: %v", err)
			}
			if table.expectedState != state {
				t.Fatalf("got: %v, want: %v", state, table.expectedState)
			}
		})
	}
}

func Test_IndexManifest_Failure(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
		mock          func(t *testing.T) indexer.Store
	}{
		{
			name:          "index failure",
			expectedState: Terminal,
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
			s := table.mock(t)
			indexer := New(&indexer.Opts{
				Store: s,
			})

			state, err := indexManifest(ctx, indexer)
			if err == nil {
				t.Fatalf("expected error")
			}
			if table.expectedState != state {
				t.Fatalf("got: %v, want: %v", state, table.expectedState)
			}
		})
	}
}
