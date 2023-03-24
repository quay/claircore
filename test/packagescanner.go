package test

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test/fetch"
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
//
// This function assumes the returned values must exactly match tc.Want.
// If tc.Want only covers a subset of potential returned values, then
// use RunSubset.
func (tc ScannerTestcase) Run(ctx context.Context) func(*testing.T) {
	sort.Slice(tc.Want, pkgSort(tc.Want))
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
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
		sort.Slice(got, pkgSort(got))
		t.Logf("found %d packages", len(got))
		if !cmp.Equal(tc.Want, got) {
			t.Error(cmp.Diff(tc.Want, got))
		}
	}
}

// RunSubset returns a function suitable for using with (*testing.T).Run.
//
// This function is similar to except it assumes tc.Want is a subset of
// all potential values.
// n is the total number of expected packages, ie len(got).
func (tc ScannerTestcase) RunSubset(ctx context.Context, n int) func(*testing.T) {
	sort.Slice(tc.Want, pkgSort(tc.Want))
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		d := tc.Digest()
		f, err := fetch.Layer(ctx, t, http.DefaultClient, tc.Domain, tc.Name, d)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		l := &claircore.Layer{
			Hash: d,
		}
		l.SetLocal(f.Name())

		got, err := tc.Scanner.Scan(ctx, l)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("found %d packages", len(got))
		if !cmp.Equal(n, len(got)) {
			t.Error(cmp.Diff(n, len(got)))
		}

		type key struct {
			name, hint string
		}
		gotMap := make(map[key]*claircore.Package, len(got))
		for _, p := range got {
			gotMap[key{
				name: p.Name,
				hint: p.RepositoryHint,
			}] = p
		}

		for _, p := range tc.Want {
			g, exists := gotMap[key{
				name: p.Name,
				hint: p.RepositoryHint,
			}]
			if !exists {
				t.Error(fmt.Sprintf("got is missing package %s with hint %s", p.Name, p.RepositoryHint))
				continue
			}

			if !cmp.Equal(p, g) {
				t.Error(cmp.Diff(p, g))
			}
		}
	}
}

func pkgSort(s []*claircore.Package) func(i, j int) bool {
	return func(i, j int) bool {
		switch strings.Compare(s[i].Name, s[j].Name) {
		case -1:
			return true
		case 0:
			return strings.Compare(s[i].RepositoryHint, s[j].RepositoryHint) == -1
		default:
		}
		return false
	}
}
