package mock_indexer

import (
	indexer "github.com/quay/claircore/indexer"
)

type (
	Opts                = indexer.Opts
	Store               = indexer.Store
	LayerScanner        = indexer.LayerScanner
	PackageScanner      = indexer.PackageScanner
	VersionedScanner    = indexer.VersionedScanner
	DistributionScanner = indexer.DistributionScanner
	RepositoryScanner   = indexer.RepositoryScanner
	Coalescer           = indexer.Coalescer
	Ecosystem           = indexer.Ecosystem
	Realizer            = indexer.Realizer
)
