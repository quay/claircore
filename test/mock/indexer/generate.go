package mock_indexer

//go:generate -command mockgen go run go.uber.org/mock/mockgen -destination=./mocks.go github.com/quay/claircore/indexer
//go:generate mockgen Store,PackageScanner,VersionedScanner,DistributionScanner,RepositoryScanner,Coalescer,Realizer,FetchArena
