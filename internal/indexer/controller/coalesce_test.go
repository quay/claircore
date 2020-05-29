package controller

import (
	"context"
	"testing"

	"github.com/quay/claircore/internal/indexer"
)

// Test_Coalesce confirms when no error is encountered
// the the coalesce method will transition to the correct
// state
//
// this test simply provides no Ecosystems to the index
// controller and does no work.
func Test_Coalesce(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
	}{
		{
			name:          "successful index",
			expectedState: IndexManifest,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			indexer := New(&indexer.Opts{})

			state, err := coalesce(ctx, indexer)
			if err != nil {
				t.Fatalf("did not expect error: %v", err)
			}
			if table.expectedState != state {
				t.Fatalf("got: %s, wanted: %s", table.expectedState, state)
			}
		})
	}
}
