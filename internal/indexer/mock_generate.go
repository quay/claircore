package indexer

//go:generate -command mockgen mockgen -package=indexer -self_package=github.com/quay/claircore/internal/indexer
//go:generate mockgen -destination=./store_mock.go github.com/quay/claircore/internal/indexer Store
//go:generate mockgen -destination=./fetcher_mock.go github.com/quay/claircore/internal/indexer Fetcher
//go:generate mockgen -destination=./layerscanner_mock.go github.com/quay/claircore/internal/indexer LayerScanner
//go:generate mockgen -destination=./packagescanner_mock.go github.com/quay/claircore/internal/indexer PackageScanner
//go:generate mockgen -destination=./versionedscanner_mock.go github.com/quay/claircore/internal/indexer VersionedScanner
//go:generate mockgen -destination=./distributionscanner_mock.go github.com/quay/claircore/internal/indexer DistributionScanner
//go:generate mockgen -destination=./reposcanner_mock.go github.com/quay/claircore/internal/indexer RepositoryScanner
//go:generate mockgen -destination=./coalescer_mock.go github.com/quay/claircore/internal/indexer Coalescer
