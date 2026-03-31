package mock_driver

//go:generate -command mockgen go tool mockgen -package=$GOPACKAGE -destination=./mocks.go github.com/quay/claircore/libvuln/driver
//go:generate mockgen Matcher
