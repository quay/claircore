package mock_indexer

//go:generate -command mockgen go run github.com/golang/mock/mockgen -destination=./mocks.go github.com/quay/claircore/indexer
//go:generate mockgen Store,PackageScanner,VersionedScanner,DistributionScanner,RepositoryScanner,Coalescer,Realizer,FetchArena
