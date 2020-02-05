package postgres

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

type scannerTestcase struct {
	// the name of this test
	name string
	// the manifest hash
	hash claircore.Digest
	// the number of scanners linked to a manifest
	scanners int
}

func Test_ManifestScanned_Failure(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()

	var tt = []scannerTestcase{
		{
			name:     "one scanner",
			hash:     randomHash(t),
			scanners: 1,
		},
		{
			name:     "two scanners",
			hash:     randomHash(t),
			scanners: 2,
		},
		{
			name:     "five scanners",
			hash:     randomHash(t),
			scanners: 5,
		},
		{
			name:     "ten scanners",
			hash:     randomHash(t),
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

	var tt = []scannerTestcase{
		{
			name:     "one scanner",
			hash:     randomHash(t),
			scanners: 1,
		},
		{
			name:     "two scanners",
			hash:     randomHash(t),
			scanners: 2,
		},
		{
			name:     "five scanners",
			hash:     randomHash(t),
			scanners: 5,
		},
		{
			name:     "ten scanners",
			hash:     randomHash(t),
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
