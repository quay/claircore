package mock_datastore

//go:generate -command mockgen go run go.uber.org/mock/mockgen -destination=./mocks.go github.com/quay/claircore/datastore
//go:generate mockgen Enrichment,EnrichmentUpdater,MatcherStore,Updater,Vulnerability
