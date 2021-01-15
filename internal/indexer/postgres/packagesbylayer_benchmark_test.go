package postgres

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func Benchmark_PackagesByLayer(b *testing.B) {
	integration.Skip(b)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	benchmarks := []struct {
		name  string
		hash  claircore.Digest
		pkgs  int
		scnrs int
	}{
		{
			name:  "10 package, 5 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  10,
			scnrs: 5,
		},
		{
			name:  "50 packages, 25 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  50,
			scnrs: 25,
		},
		{
			name:  "100 packages, 50 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  100,
			scnrs: 50,
		},
		{
			name:  "500 packages, 250 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  500,
			scnrs: 250,
		},
		{
			name:  "1000 packages, 500 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  1000,
			scnrs: 500,
		},
		{
			name:  "2000 packages, 1000 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  2000,
			scnrs: 1000,
		},
		{
			name:  "3000 packages, 2000 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  3000,
			scnrs: 1000,
		},
		{
			name:  "3000 packages, 500 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  3000,
			scnrs: 500,
		},
		{
			name:  "3000 packages, 250 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  3000,
			scnrs: 250,
		},
		{
			name:  "3000 packages, 50 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  2000,
			scnrs: 50,
		},
		{
			name:  "3000 packages, 10 scanners",
			hash:  test.RandomSHA256Digest(b),
			pkgs:  2000,
			scnrs: 10,
		},
	}

	for _, bench := range benchmarks {
		b.Run(bench.name, func(b *testing.B) {
			ctx := zlog.Test(ctx, b)
			pool := TestDatabase(ctx, b)
			store := NewStore(pool)

			// generate a specific number of packages
			pkgs := test.GenUniquePackages(bench.pkgs)

			// index them into the database
			err := pgtest.InsertPackages(ctx, pool, pkgs)
			if err != nil {
				b.Fatalf("failed to insert packages: %v", err)
			}

			// create scnr mocks
			vscnrs := test.GenUniquePackageScanners(bench.scnrs)
			err = pgtest.InsertUniqueScanners(ctx, pool, vscnrs)
			if err != nil {
				b.Fatalf("failed to insert scnrs: %v", err)
			}

			// create scanartifacts
			err = pgtest.InsertPackageScanArtifacts(ctx, pool, bench.hash, pkgs, vscnrs)
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
