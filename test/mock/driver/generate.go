package mock_driver

//go:generate -command mockgen go run github.com/golang/mock/mockgen -destination=./mocks.go github.com/quay/claircore/libvuln/driver
//go:generate mockgen Matcher
