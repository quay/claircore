package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/test/integration"
)

func Test_PutHash_Upsert(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
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
		db, store, _, teardown := TestStore(ctx, t)
		defer teardown()

		for i := 0; i < table.iterations; i++ {
			// put k,v
			key := uuid.New().String()
			value := uuid.New().String()

			err := store.PutHash(key, value)
			assert.NoError(t, err)

			// check key
			var v string
			err = db.Get(&v, selectHash, key)
			if err != nil {
				t.Fatalf("failed to PUT hash: %v", err)
			}
			assert.Equal(t, value, v)

			// update value
			value = uuid.New().String()
			err = store.PutHash(key, value)
			assert.NoError(t, err)

			// check key
			err = db.Get(&v, selectHash, key)
			if err != nil {
				t.Fatalf("failed to PUT hash: %v", err)
			}
			assert.Equal(t, value, v)

			// update value
			value = uuid.New().String()
			err = store.PutHash(key, value)
			assert.NoError(t, err)

			// check key
			err = db.Get(&v, selectHash, key)
			if err != nil {
				t.Fatalf("failed to PUT hash: %v", err)
			}
			assert.Equal(t, value, v)
		}
	}
}

func Test_PutHash_Insert(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
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
		db, store, _, teardown := TestStore(ctx, t)
		defer teardown()

		for i := 0; i < table.iterations; i++ {
			// put k,v
			key := uuid.New().String()
			value := uuid.New().String()

			err := store.PutHash(key, value)
			assert.NoError(t, err)

			// check key
			var v string
			err = db.Get(&v, selectHash, key)
			if err != nil {
				t.Fatalf("failed to PUT hash: %v", err)
			}
			assert.Equal(t, value, v)
		}
	}
}
