package mock_driver

//go:generate -command mockgen mockgen -destination=./mocks.go github.com/quay/claircore/libvuln/driver
//go:generate mockgen Matcher
