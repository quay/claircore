package mock_updater

//go:generate -command mockgen mockgen -package=$GOPACKAGE -destination=./mocks.go github.com/quay/claircore/updater
//go:generate mockgen Store
