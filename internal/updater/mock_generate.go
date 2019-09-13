package updater

//go:generate -command mockgen mockgen -package=updater -self_package=github.com/quay/claircore/internal/updater
//go:generate mockgen -destination=./updater_mock.go github.com/quay/claircore/internal/updater Updater
//go:generate mockgen -destination=./fetcher_mock.go github.com/quay/claircore/internal/updater Fetcher
//go:generate mockgen -destination=./parser_mock.go github.com/quay/claircore/internal/updater Parser
