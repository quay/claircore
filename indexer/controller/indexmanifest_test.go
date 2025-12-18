package controller

import (
	"fmt"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/quay/claircore/test"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

func TestIndexManifest(t *testing.T) {
	tt := []struct {
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
			ctx := test.Logging(t)
			s := table.mock(t)
			indexer := New(&indexer.Options{
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
