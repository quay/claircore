package mock_driver

//go:generate -command mockgen go run go.uber.org/mock/mockgen -destination=./mocks.go github.com/quay/claircore/libvuln/driver
//go:generate mockgen Matcher
