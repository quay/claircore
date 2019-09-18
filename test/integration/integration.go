// Package integration is a helper for running integration tests.
package integration

import "testing"

// Skip will skip the current test or benchmark if this package was built with
// the "integration" build tag.
//
// This should be used as an annotation at the top of the function, like
// (*testing.T).Parallel().
//
//	func TestThatTouchesNetwork(t *testing.T) {
//		t.Parallel()
//		integration.Skip(t)
//		// ...
//	}
func Skip(t testing.TB) {
	if skip {
		t.Skip("skipping integration test")
	}
}
