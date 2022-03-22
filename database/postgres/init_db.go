package postgres

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"path"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
)

type (
	MatcherDB pgxpool.Pool
	IndexerDB pgxpool.Pool
)

var (
	// go:embed migrations/matcher
	matcherSQL embed.FS
	// go:embed migrations/indexer
	indexerSQL embed.FS
)

func InitMatcherDB(ctx context.Context, pool *pgxpool.Pool) (*MatcherDB, error) {
	const name = "libvuln_migrations"
	if err := runMigrations(ctx, name, matcherSQL, pool.Config().ConnConfig); err != nil {
		return nil, err
	}
	return (*MatcherDB)(pool), nil
}

func InitIndexerDB(ctx context.Context, pool *pgxpool.Pool) (*IndexerDB, error) {
	const name = "libindex_migrations"
	if err := runMigrations(ctx, name, indexerSQL, pool.Config().ConnConfig); err != nil {
		return nil, err
	}
	return (*IndexerDB)(pool), nil
}

func runMigrations(ctx context.Context, name string, sys fs.FS, cfg *pgx.ConnConfig) error {
	ctx = zlog.ContextWithValues(ctx, "table", name)
	var ms []migrate.Migration
	err := fs.WalkDir(sys, ".", func(p string, ent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ent.IsDir() {
			return fs.SkipDir
		}
		if ok, _ := path.Match("*.sql", ent.Name()); !ok {
			return nil
		}
		b, err := fs.ReadFile(sys, p)
		if err != nil {
			return err
		}
		fn := ent.Name()
		i := len(ms) + 1
		ms = append(ms, migrate.Migration{
			ID: i,
			Up: func(tx *sql.Tx) error {
				zlog.Debug(ctx).
					Str("migration", fn).
					Int("n", i).
					Msg("migration start")
				_, err := tx.Exec(string(b))
				zlog.Debug(ctx).
					Str("migration", fn).
					Int("n", i).
					Err(err).
					Msg("migration done")
				if err != nil {
					return err
				}
				return nil
			},
		})
		return nil
	})
	zlog.Info(ctx).
		Int("count", len(ms)).
		Err(err).
		Msg("migrations queued")
	if err != nil {
		return err
	}

	db, err := sql.Open("pgx", stdlib.RegisterConnConfig(cfg))
	if err != nil {
		return err
	}
	defer db.Close()
	migrator := migrate.NewPostgresMigrator(db)
	migrator.Table = name
	err = migrator.Exec(migrate.Up, ms...)
	zlog.Info(ctx).
		Int("count", len(ms)).
		Err(err).
		Msg("migrations done")
	if err != nil {
		return err
	}
	return nil
}
