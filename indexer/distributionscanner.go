package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// DistributionScanner reports the Distributions found in a given layer.
type DistributionScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Distribution, error)
}
