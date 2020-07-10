package test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/claircore/test/log"
)

// ScannerTestcase can be used for testing layers found in the wild against a
// scanner.
//
// Tests that use this struct should not be marked as integration tests, as the
// Run method does that internally if it needs to talk to the network.
type ScannerTestcase struct {
	Domain  string
	Name    string
	Hash    string
	Want    []*claircore.Package
	Scanner indexer.PackageScanner
}

// Digest reports the digest in the Hash member.
//
// Panics if an error is returned from ParseDigest.
func (tc ScannerTestcase) Digest() claircore.Digest {
	d, err := claircore.ParseDigest(tc.Hash)
	if err != nil {
		panic(err)
	}
	return d
}

// Run returns a function suitable for using with (*testing.T).Run.
func (tc ScannerTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx, done := log.TestLogger(ctx, t)
		defer done()
		d := tc.Digest()
		n, err := fetch.Layer(ctx, t, http.DefaultClient, tc.Domain, tc.Name, d)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		l := &claircore.Layer{
			Hash: d,
		}
		l.SetLocal(n.Name())

		got, err := tc.Scanner.Scan(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("found %d packages", len(got))
		if !cmp.Equal(tc.Want, got) {
			t.Error(cmp.Diff(tc.Want, got))
		}
	}
}
