// Package integration is a helper for running integration tests.
package integration

import (
	"testing"
)

// Skip will skip the current test or benchmark if this package was built without
// the "integration" build tag.
//
// This should be used as an annotation at the top of the function, like
// (*testing.T).Parallel().
//
// See the example for usage.
func Skip(t testing.TB) {
	if skip {
		t.Skip("skipping integration test: integration tag not provided")
	}
}
