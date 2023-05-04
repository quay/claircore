package mock_indexer

import (
	indexer "github.com/quay/claircore/indexer"
)

type (
	Options             = indexer.Options
	Store               = indexer.Store
	LayerScanner        = indexer.LayerScanner
	PackageScanner      = indexer.PackageScanner
	VersionedScanner    = indexer.VersionedScanner
	DistributionScanner = indexer.DistributionScanner
	RepositoryScanner   = indexer.RepositoryScanner
	Coalescer           = indexer.Coalescer
	Ecosystem           = indexer.Ecosystem
	Realizer            = indexer.Realizer
	FetchArena          = indexer.FetchArena
)
