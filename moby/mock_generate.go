package moby

//go:generate -command mockgen mockgen -package=moby -self_package=github.com/quay/claircore/moby
//go:generate mockgen -destination=./archiver_mock.go github.com/quay/claircore/moby Archiver
//go:generate mockgen -destination=./stacker_mock.go github.com/quay/claircore/moby Stacker
