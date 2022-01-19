package mock_indexer

//go:generate -command mockgen mockgen -destination=./mocks.go github.com/quay/claircore/internal/indexer
//go:generate mockgen Store,Fetcher,LayerScanner,PackageScanner,VersionedScanner,DistributionScanner,RepositoryScanner,Coalescer
