package mock_driver

//go:generate -command mockgen go run github.com/golang/mock/mockgen -package=$GOPACKAGE -destination=./mocks.go github.com/quay/claircore/updater/driver/v1
//go:generate mockgen Updater,UpdaterFactory,VulnerabilityParser,EnrichmentParser
