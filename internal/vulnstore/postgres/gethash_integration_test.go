package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_GetHash_KeyNotExists(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	var tt = []struct {
		name       string
		iterations int
	}{
		{
			name:       "100 iterations uuid",
			iterations: 100,
		},
		{
			name:       "1000 iterations uuid",
			iterations: 1000,
		},
	}
	for _, table := range tt {
		_, store, _, teardown := TestStore(ctx, t)
		defer teardown()

		for i := 0; i < table.iterations; i++ {
			// put k,v
			key := uuid.New().String()

			// attempt get k,v
			v, err := store.GetHash(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := v, ""; got != want {
				t.Fatalf("got: %q, want: %q", got, want)
			}
		}
	}
}

func Test_GetHash_KeyExists(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	var tt = []struct {
		// the name of the test
		name string
		// how many times to generate a uuid and test
		iterations int
	}{
		{
			name:       "100 iterations uuid",
			iterations: 100,
		},
		{
			name:       "1000 iterations uuid",
			iterations: 1000,
		},
	}

	for _, table := range tt {
		db, store, _, teardown := TestStore(ctx, t)
		defer teardown()

		for i := 0; i < table.iterations; i++ {
			// put k,v
			key := uuid.New().String()
			value := uuid.New().String()
			_, err := db.Exec(upsertHash, key, value)
			if err != nil {
				t.Fatalf("failed to PUT hash: %v", err)
			}

			// attempt get k,v
			v, err := store.GetHash(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := v, value; got != want {
				t.Fatalf("got: %q, want: %q", got, want)
			}
		}
	}
}
