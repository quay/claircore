package datastore_test

import (
	"context"
	"testing"

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
