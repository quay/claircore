// +build integration

package integration

func init() {
	// if this file is built flip skip bool to run integration tests
	skip = false
}
