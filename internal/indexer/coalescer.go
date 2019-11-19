package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// Coalescer takes a set of layers and creates coalesced IndexReport.
//
// A coalesced IndexReport should provide only the packages present in the
// final container image once all layers were applied.
type Coalescer interface {
	Coalesce(ctx context.Context, layers []*claircore.Layer) (*claircore.IndexReport, error)
}
