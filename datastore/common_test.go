package datastore_test

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore"
)

// These are the implementations of [datastore] interfaces under test.
var (
	MatcherImplementations = []NewStoreFunc[datastore.MatcherV1]{
		NewPostgresV1[datastore.MatcherV1],
		NewPostgresV2[datastore.MatcherV1],
	}
	IndexerImplementations = []NewStoreFunc[datastore.IndexerV1]{
		NewPostgresV1[datastore.IndexerV1],
		NewPostgresV2[datastore.IndexerV1],
	}
)

// NewStoreFunc is a function type describing a constructor for one of the
// [datastore] interfaces.
//
// BUG(hank): Due to the current lack of sum types, the type constraint for
// [NewStoreFunc] is overly broad and implementations may panic at runtime when
// called with unexpected type parameters.
type NewStoreFunc[T any] func(context.Context, testing.TB) T

// TestFunc is a function type describing a function that is an individual call
// to a [datastore] API that returns something for comparison.
//
// BUG(hank): Due to the current lack of sum types, the "S" type constraint for
// [TestFunc] is overly broad and implementations may panic at runtime when
// called with unexpected type parameters.
type TestFunc[S any, T any] func(context.Context, *testing.T, S) T

// FuncName reports the name of the passed function. Also handles methods.
func funcName(f any) (n string) {
	n = runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	n = n[strings.LastIndexByte(n, '.')+1:]
	n = strings.TrimSuffix(n, "-fm")
	return n
}

type State[Store any, Per PerStore[Store]] interface {
	CmpOpts() cmp.Options
	PerStore() []Per
}

type PerStore[Store any] interface {
	Name() string
	Store() Store
}

// ForEachStore runs the function "inner" for each Store in "st" and compares
// the result using go-cmp.
func forEachStore[Store any, Return any, Per PerStore[Store], St State[Store, Per]](
	ctx context.Context, st St, inner TestFunc[Store, Return]) func(*testing.T) {
	name := funcName(inner)
	return func(t *testing.T) {
		per := st.PerStore()
		if len(per) == 1 {
			t.Fatal("only one store implementation provided")
		}
		// Run a subtest named for the function passed in.
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			got := make([]Return, len(per))
			for i, p := range per {
				out := &got[i]
				// Run a subtest per store instance.
				t.Run(p.Name(), func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					*out = inner(ctx, t, p.Store())
				})
			}
			if t.Failed() {
				t.FailNow()
			}

			// Compare the results pairwise for every combination.
			// This will get slower with more implementations.
			// It may not be necessary to do every combination, but it should be more informative.
			opts := st.CmpOpts()
			for i, lim := 0, len(per); i < lim-1; i++ {
				for j := i + 1; j < lim; j++ {
					a, b := per[i], per[j]
					aOut, bOut := got[i], got[j]
					ok := cmp.Equal(aOut, bOut, opts)
					if !ok {
						t.Logf("%s ≇ %s", a.Name(), b.Name())
						t.Error(cmp.Diff(aOut, bOut, opts))
					} else {
						t.Logf("%s ≅ %s", a.Name(), b.Name())
					}
				}
			}
		})
	}
}
