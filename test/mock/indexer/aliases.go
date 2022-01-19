package mock_indexer

import indexer "github.com/quay/claircore/internal/indexer"

type (
	Opts                = indexer.Opts
	Store               = indexer.Store
	Fetcher             = indexer.Fetcher
	LayerScanner        = indexer.LayerScanner
	PackageScanner      = indexer.PackageScanner
	VersionedScanner    = indexer.VersionedScanner
	DistributionScanner = indexer.DistributionScanner
	RepositoryScanner   = indexer.RepositoryScanner
	Coalescer           = indexer.Coalescer
	Ecosystem           = indexer.Ecosystem
)
