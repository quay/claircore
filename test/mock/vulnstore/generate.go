package mock_vulnstore

//go:generate -command mockgen mockgen -destination=./mocks.go github.com/quay/claircore/internal/vulnstore
//go:generate mockgen Updater
