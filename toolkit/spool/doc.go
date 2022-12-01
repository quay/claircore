// Package spool provides utilities for managing file lifecycles.
package spool

import (
	"io"
	"runtime/pprof"
)

// BUG(hank) Close methods currently swallow most errors. This should be fixed
// when native error tree support lands in Go 1.20.

// This package uses profiles instead of panicing finalizers because Arenas keep
// live pointers, which would prevent the finalizers working correctly, anyway.

const pprofPrefix = `github.com/quay/claircore/pkg/spool.`

// Profiling support:
var (
	aProfile = pprof.NewProfile(pprofPrefix + "Arena")
	dProfile = pprof.NewProfile(pprofPrefix + "Dir")
	fProfile = pprof.NewProfile(pprofPrefix + "File")
)

// Some interface asserts:
var (
	_ io.Closer = (*Arena)(nil)
	_ io.Closer = (*Dir)(nil)
	_ io.Closer = (*File)(nil)
)
