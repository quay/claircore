package indexer

import (
	"context"

	"github.com/quay/claircore"
)

type DistributionScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Distribution, error)
}
