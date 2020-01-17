package postgres

import (
	"context"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Benchmark_PackagesByLayer(b *testing.B) {
	integration.Skip(b)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	benchmarks := []struct {
		name  string
		hash  string
		pkgs  int
		scnrs int
	}{
		{
			name:  "10 package, 5 scanners",
			hash:  "test-layer-hash",
			pkgs:  10,
			scnrs: 5,
		},
		{
			name:  "50 packages, 25 scanners",
			hash:  "test-layer-hash",
			pkgs:  50,
			scnrs: 25,
		},
		{
			name:  "100 packages, 50 scanners",
			hash:  "test-layer-hash",
			pkgs:  100,
			scnrs: 50,
		},
		{
			name:  "500 packages, 250 scanners",
			hash:  "test-layer-hash",
			pkgs:  500,
			scnrs: 250,
		},
		{
			name:  "1000 packages, 500 scanners",
			hash:  "test-layer-hash",
			pkgs:  1000,
			scnrs: 500,
		},
		{
			name:  "2000 packages, 1000 scanners",
			hash:  "test-layer-hash",
			pkgs:  2000,
			scnrs: 1000,
		},
		{
			name:  "3000 packages, 2000 scanners",
			hash:  "test-layer-hash",
			pkgs:  3000,
			scnrs: 1000,
		},
		{
			name:  "3000 packages, 500 scanners",
			hash:  "test-layer-hash",
			pkgs:  3000,
			scnrs: 500,
		},
		{
			name:  "3000 packages, 250 scanners",
			hash:  "test-layer-hash",
			pkgs:  3000,
			scnrs: 250,
		},
		{
			name:  "3000 packages, 50 scanners",
			hash:  "test-layer-hash",
			pkgs:  2000,
			scnrs: 50,
		},
		{
			name:  "3000 packages, 10 scanners",
			hash:  "test-layer-hash",
			pkgs:  2000,
			scnrs: 10,
		},
	}

	for _, bench := range benchmarks {
		b.Run(bench.name, func(b *testing.B) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, b)
			db, store, _, teardown := TestStore(ctx, b)
			defer teardown()

			// generate a specific number of packages
			pkgs := test.GenUniquePackages(bench.pkgs)

			// index them into the database
			err := pgtest.InsertPackages(db, pkgs)
			if err != nil {
				b.Fatalf("failed to insert packages: %v", err)
			}

			// create scnr mocks
			vscnrs := test.GenUniquePackageScanners(bench.scnrs)
			err = pgtest.InsertUniqueScanners(db, vscnrs)
			if err != nil {
				b.Fatalf("failed to insert scnrs: %v", err)
			}

			// create scanartifacts
			err = pgtest.InsertPackageScanArtifacts(db, bench.hash, pkgs, vscnrs)
			if err != nil {
				b.Fatalf("failed to insert scan artifacts for test: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := store.PackagesByLayer(ctx, bench.hash, vscnrs)
				if err != nil {
					b.Fatalf("failed to retrieve packages by layer: %v", err)
				}
			}
		})
	}
}
