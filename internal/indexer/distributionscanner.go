package indexer

import "github.com/quay/claircore"

type DistributionScanner interface {
	VersionedScanner
	Scan(*claircore.Layer) ([]*claircore.Distribution, error)
}
