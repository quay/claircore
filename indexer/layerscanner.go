package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// LayerScanner is an interface for scanning a set of layer's contents and indexing
// discovered items into the persistence layer. scanning mechanics (concurrency, ordering, etc...)
// will be defined by implementations.
type LayerScanner interface {
	Scan(ctx context.Context, manifest claircore.Digest, layers []*claircore.Layer) error
}
