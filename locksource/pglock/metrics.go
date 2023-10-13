package pglock

import "runtime/pprof"

// As a style note, this package avoids using the pprof.Do helper because it
// makes the stack trace names *much* worse.

const (
	pkgname    = `github.com/quay/claircore/locksource/pglock`
	tracelabel = pkgname + `.Locker`
)

var profile = pprof.NewProfile(pkgname + `.Lock`)
