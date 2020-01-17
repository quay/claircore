package postgres

import (
	"context"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Test_ManifestScanned_Failure(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	const hash = `deadbeef`

	var tt = []struct {
		// the name of this test
		name string
		// the manifest hash
		hash string
		// the number of scanners linked to a manifest
		scanners int
	}{
		{
			name:     "one scanner",
			hash:     hash,
			scanners: 1,
		},
		{
			name:     "two scanners",
			hash:     hash,
			scanners: 2,
		},
		{
			name:     "five scanners",
			hash:     hash,
			scanners: 5,
		},
		{
			name:     "ten scanners",
			hash:     hash,
			scanners: 10,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			vscnrs := test.GenUniquePackageScanners(table.scanners)
			err := pgtest.InsertUniqueScanners(db, vscnrs)
			if err != nil {
				t.Fatal(err)
			}

			ok, err := store.ManifestScanned(ctx, table.hash, vscnrs)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Fatal("expected false from ManifestScanned")
			}
		})
	}
}

func Test_ManifestScanned_Success(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	const hash = `deafbeef`

	var tt = []struct {
		// the name of this test
		name string
		// the manifest hash
		hash string
		// the number of scanners linked to a manifest
		scanners int
	}{
		{
			name:     "one scanner",
			hash:     hash,
			scanners: 1,
		},
		{
			name:     "two scanners",
			hash:     hash,
			scanners: 2,
		},
		{
			name:     "five scanners",
			hash:     hash,
			scanners: 5,
		},
		{
			name:     "ten scanners",
			hash:     hash,
			scanners: 10,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			vscnrs := test.GenUniquePackageScanners(table.scanners)
			if err := pgtest.InsertUniqueScanners(db, vscnrs); err != nil {
				t.Fatal(err)
			}
			if err := pgtest.InsertScannerList(db, table.hash, table.scanners); err != nil {
				t.Fatal(err)
			}

			ok, err := store.ManifestScanned(ctx, table.hash, vscnrs)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected true from ManifestScanned")
			}
		})
	}
}
