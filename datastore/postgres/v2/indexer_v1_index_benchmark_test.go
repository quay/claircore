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

func Benchmark_IndexPackages(b *testing.B) {
	integration.NeedDB(b)
	ctx := context.Background()
	benchmarks := []struct {
		// the name of this benchmark
		name string
		// number of packages to index.
		pkgs int
		// the layer that holds the discovered packages
		layer *claircore.Layer
		// whether the generated package array contains duplicate packages
		duplicates bool
	}{
		{
			name: "10 packages",
			pkgs: 10,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "10 packages with duplicates",
			pkgs: 10,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "50 packages",
			pkgs: 50,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "50 packages with duplicates",
			pkgs: 50,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "100 packages",
			pkgs: 100,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "100 packages with duplicates",
			pkgs: 100,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "250 packages",
			pkgs: 250,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "250 packages",
			pkgs: 250,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "500 packages",
			pkgs: 500,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "500 packages with duplicates",
			pkgs: 500,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "1000 packages",
			pkgs: 1000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "1000 packages with duplicates",
			pkgs: 1000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "2000 packages",
			pkgs: 2000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "2000 packages with duplicates",
			pkgs: 2000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "3000 packages",
			pkgs: 3000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "3000 packages with duplicates",
			pkgs: 3000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "4000 packages",
			pkgs: 4000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "4000 packages with duplicates",
			pkgs: 4000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
		},
		{
			name: "5000 packages",
			pkgs: 5000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
		},
		{
			name: "5000 packages with duplicates",
			pkgs: 5000,
			layer: &claircore.Layer{
				Hash: test.RandomSHA256Digest(b),
			},
			duplicates: true,
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

			ps := pgtest.Generate[indexer.PackageScanner](ctx, 1)
			err = pgx.BeginFunc(ctx, pool, ps.Exec)
			if err != nil {
				b.Fatalf("failed to insert scanners: %v", err)
			}
			var vs []indexer.VersionedScanner
			err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT name, version, kind FROM scanner WHERE id = ANY($1)`, ps.IDs())
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

			// gen packages
			var pkgs []*claircore.Package
			if bench.duplicates {
				pkgs, err = test.GenDuplicatePackages(bench.pkgs)
				if err != nil {
					b.Fatalf("failed to generate duplicate packages: %v", err)
				}
			} else {
				pkgs = test.GenUniquePackages(bench.pkgs)
			}

			// insert layer
			insertLayer := `INSERT INTO layer (hash) VALUES ($1);`
			_, err = pool.Exec(ctx, insertLayer, bench.layer.Hash)
			if err != nil {
				b.Fatalf("failed to insert test layer: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// run the indexing
				err = store.IndexPackages(ctx, pkgs, bench.layer, vs[0])
				if err != nil {
					b.Fatalf("failed to index packages: %v", err)
				}
			}
		})
	}

}
