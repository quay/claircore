package distlock

//go:generate mockgen -package=distlock -self_package=github.com/quay/claircore/pkg/distlock -destination=./locker_mock.go github.com/quay/claircore/pkg/distlock Locker
