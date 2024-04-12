package datastore_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/datastore/postgres"
	pgtest "github.com/quay/claircore/test/postgres"
)

// NewPostgresV1 implements [NewStoreFunc] for the [postgres] package.
func NewPostgresV1[T any](ctx context.Context, t testing.TB) T {
	// TODO(hank): go1.22: Use [reflect.TypeFor] throughout.
	var out T
	switch typ := reflect.TypeOf((*T)(nil)).Elem(); typ {
	case reflect.TypeOf((*datastore.MatcherV1)(nil)).Elem(),
		reflect.TypeOf((*datastore.MatcherV1Updater)(nil)).Elem(),
		reflect.TypeOf((*datastore.MatcherV1Enrichment)(nil)).Elem(),
		reflect.TypeOf((*datastore.MatcherV1EnrichmentUpdater)(nil)).Elem(),
		reflect.TypeOf((*datastore.MatcherV1Vulnerability)(nil)).Elem():

		pool := pgtest.TestMatcherDB(ctx, t)
		store := postgres.NewMatcherStore(pool)
		t.Cleanup(func() {
			pool.Close()
		})
		out = any(store).(T)

	case reflect.TypeOf((*datastore.IndexerV1)(nil)).Elem(),
		reflect.TypeOf((*datastore.IndexerV1Setter)(nil)).Elem(),
		reflect.TypeOf((*datastore.IndexerV1Querier)(nil)).Elem(),
		reflect.TypeOf((*datastore.IndexerV1Artifact)(nil)).Elem():

		pool := pgtest.TestIndexerDB(ctx, t)
		store := postgres.NewIndexerStore(pool)
		t.Cleanup(func() {
			if err := store.Close(ctx); err != nil {
				t.Error(err)
			}
			pool.Close()
		})
		out = any(store).(T)

	default:
		t.Fatalf("unknown type parameter: %v", typ)
	}
	return out
}
