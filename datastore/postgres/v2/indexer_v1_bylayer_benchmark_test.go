package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres/v2"
)

func Benchmark_PackagesByLayer(b *testing.B) {
	integration.NeedDB(b)
	ctx := context.Background()
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
			cfg := pgtest.TestIndexerDB(ctx, b)
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer pool.Close()
			store, err := NewIndexerV1(ctx, cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close(ctx)

			pkgs := pgtest.Generate[claircore.Package](ctx, bench.pkgs)
			err = pgx.BeginFunc(ctx, pool, pkgs.Exec)
			if err != nil {
				b.Fatalf("failed to insert packages: %v", err)
			}

			ps := pgtest.Generate[indexer.PackageScanner](ctx, bench.scnrs)
			err = pgx.BeginFunc(ctx, pool, ps.Exec)
			if err != nil {
				b.Fatalf("failed to insert scanners: %v", err)
			}
			var vs []indexer.VersionedScanner
			err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT name, version, kind FROM scanner WHERE id = ANY($1)`, ps.IDs)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var m mockScanner
					if err := rows.Scan(&m.name, &m.version, &m.kind); err != nil {
						return err
					}
					vs = append(vs, &m)
				}
				return rows.Err()
			})
			if err != nil {
				b.Fatalf("failed to read back scanners: %v", err)
			}

			// create scanartifacts
			err = pgx.BeginFunc(ctx, pool, pgtest.CreatePackageScanArtifacts(ctx, bench.hash, pkgs.IDs(), ps.IDs()))
			if err != nil {
				b.Fatalf("failed to insert scan artifacts for test: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := store.PackagesByLayer(ctx, bench.hash, vs)
				if err != nil {
					b.Fatalf("failed to retrieve packages by layer: %v", err)
				}
			}
		})
	}
}

type mockScanner struct {
	name, version, kind string
}

func (m *mockScanner) Name() string    { return m.name }
func (m *mockScanner) Version() string { return m.version }
func (m *mockScanner) Kind() string    { return m.kind }
