package mock_indexer

//go:generate -command mockgen go tool mockgen -package=$GOPACKAGE -destination=./mocks.go github.com/quay/claircore/indexer
//go:generate mockgen Store,PackageScanner,VersionedScanner,DistributionScanner,RepositoryScanner,Coalescer,Realizer,FetchArena
