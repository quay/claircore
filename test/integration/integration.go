// Package integration is a helper for running integration tests.
package integration

import (
	"os"
	"strconv"
	"testing"
)

// Skip will skip the current test or benchmark if this package was built without
// the "integration" build tag unless the "CI" environment variable is defined
// and the "short" flag is not provided.
//
// This should be used as an annotation at the top of the function, like
// (*testing.T).Parallel().
//
// See the example for usage.
func Skip(t testing.TB) {
	switch {
	case testing.Short():
		t.Skip(`skipping integration test: short tests`)
	case inCI && skip:
		t.Log(`enabling integration test: environment variable "CI" is defined`)
	case skip:
		t.Skip("skipping integration test: integration tag not provided")
	}
}

var inCI, inGHA bool

func init() {
	inCI, _ = strconv.ParseBool(os.Getenv("CI"))
	inGHA, _ = strconv.ParseBool(os.Getenv("GITHUB_ACTIONS"))
}
