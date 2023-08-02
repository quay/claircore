package fixture

import (
	"context"
	"testing"
)

func TestLookup(t *testing.T) {
	const want = `test/fixture`
	var got string
	// Simulate getting called from a top-level test:
	func() {
		got = lookupCaller(t)
	}()
	t.Logf("got: %q, want: %q", got, want)
	if got != want {
		t.Fail()
	}
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	tcs := Fetch[Indexer](ctx, t)
	for _, tc := range tcs {
		t.Logf("got layer: %v", tc.Manifest.Hash)
	}
}
