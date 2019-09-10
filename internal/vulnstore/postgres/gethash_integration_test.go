//+build integration

package postgres

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_GetHash_KeyNotExists(t *testing.T) {
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
		_, store, teardown := NewTestStore(t)
		defer teardown()

		for i := 0; i < table.iterations; i++ {
			// put k,v
			key := uuid.New().String()

			// attempt get k,v
			v, err := store.GetHash(key)
			assert.NoError(t, err)
			assert.Equal(t, "", v)
		}
	}
}

func Test_GetHash_KeyExists(t *testing.T) {
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
		db, store, teardown := NewTestStore(t)
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
			v, err := store.GetHash(key)
			assert.NoError(t, err)
			assert.Equal(t, value, v)
		}
	}
}
