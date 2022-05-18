package controller

import (
	"context"
	"testing"

	"github.com/quay/claircore/indexer"
)

// TestCoalesce confirms when no error is encountered
// the coalesce method will transition to the correct
// state.
//
// This test simply provides no Ecosystems to the index
// controller and does no work.
func TestCoalesce(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name          string
		expectedState State
	}{
		{
			name:          "Success",
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
