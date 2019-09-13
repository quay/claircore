package vulnstore

//go:generate mockgen -package=vulnstore -self_package=github.com/quay/claircore/internal/vulnstore -destination=./updater_mock.go github.com/quay/claircore/internal/vulnstore Updater
