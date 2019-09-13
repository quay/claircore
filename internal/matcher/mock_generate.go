package matcher

//go:generate mockgen -package=matcher -self_package=github.com/quay/claircore/internal/matcher -destination=./matcher_mock.go github.com/quay/claircore/libvuln/driver Matcher
