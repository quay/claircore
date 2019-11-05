package postgres

import (
	"context"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"

	"github.com/stretchr/testify/assert"
)

func Test_ManifestScanned_Failure(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []struct {
		// the name of this test
		name string
		// the manifest hash
		hash string
		// the number of scanners linked to a manifest
		scanners int
	}{
		{
			name:     "single scanner",
			hash:     "test-manifest-hash",
			scanners: 1,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 2,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 5,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 10,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			vscnrs := test.GenUniquePackageScanners(table.scanners)
			err := pgtest.InsertUniqueScanners(db, vscnrs)
			assert.NoError(t, err)

			ok, err := store.ManifestScanned(ctx, table.hash, vscnrs)
			assert.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func Test_ManifestScanned_Success(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	var tt = []struct {
		// the name of this test
		name string
		// the manifest hash
		hash string
		// the number of scanners linked to a manifest
		scanners int
	}{
		{
			name:     "single scanner",
			hash:     "test-manifest-hash",
			scanners: 1,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 2,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 5,
		},
		{
			name:     "two scanner",
			hash:     "test-manifest-hash",
			scanners: 10,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			vscnrs := test.GenUniquePackageScanners(table.scanners)
			err := pgtest.InsertUniqueScanners(db, vscnrs)
			assert.NoError(t, err)
			err = pgtest.InsertScannerList(db, table.hash, table.scanners)
			assert.NoError(t, err)

			ok, err := store.ManifestScanned(ctx, table.hash, vscnrs)
			assert.NoError(t, err)
			assert.True(t, ok)
		})
	}
}
