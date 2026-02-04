// Package migrations holds PostgreSQL migrations for databases to back
// `datastore` implementations.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"hash/crc32"
	"io/fs"

	"github.com/jackc/pgx/v5"
)

// These are the tables used to track migrations.
//
// Deprecated: use the [Indexer] and [Matcher] functions.
var (
	IndexerMigrationTable = pgx.Identifier{"libindex_migrations"}
	MatcherMigrationTable = pgx.Identifier{"libvuln_migrations"}
)

// Indexer runs migrations for an indexer database using the provided
// configuration.
func Indexer(ctx context.Context, cfg *pgx.ConnConfig) error {
	sys, err := fs.Sub(sys, "indexer")
	if err != nil {
		return fmt.Errorf("programmer error: %w", err)
	}
	return runMigrations(ctx, cfg, IndexerMigrationTable, sys)
}

// Matcher runs migrations for a matcher database using the provided
// configuration.
func Matcher(ctx context.Context, cfg *pgx.ConnConfig) error {
	sys, err := fs.Sub(sys, "matcher")
	if err != nil {
		return fmt.Errorf("programmer error: %w", err)
	}
	return runMigrations(ctx, cfg, MatcherMigrationTable, sys)
}

// RunMigrations does what it says on the tin.
func runMigrations(ctx context.Context, cfg *pgx.ConnConfig, table pgx.Identifier, sys fs.FS) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	defer conn.Close(ctx)

	queryCreateTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (version INTEGER PRIMARY KEY NOT NULL);`, table.Sanitize())
	queryCheckMigration := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE version = $1);`, table.Sanitize())
	querySetMigration := fmt.Sprintf(`INSERT INTO %s (version) VALUES ($1);`, table.Sanitize())

	key := crc32.ChecksumIEEE([]byte("migrations"))
	// Advisory lock is dropped when the connection (session) is closed.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1);`, key); err != nil {
		return fmt.Errorf("unable to obtain migration lock %x: %w", key, err)
	}
	if _, err := conn.Exec(ctx, queryCreateTable); err != nil {
		return fmt.Errorf("unable to create migration table %s: %w", table.Sanitize(), err)
	}

	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		panic("programmer error: unable to readdir")
	}
	for i, ent := range ents {
		// Our migrations are 1-based, for no particular reason.
		id := i + 1
		b, err := fs.ReadFile(sys, ent.Name())
		if err != nil {
			return fmt.Errorf("failed to perform migrations: %w", err)
		}

		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			var ok bool
			err := tx.QueryRow(ctx, queryCheckMigration, id).Scan(&ok)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}

			if _, err := tx.Exec(ctx, string(b)); err != nil {
				return err
			}

			if _, err := tx.Exec(ctx, querySetMigration, id); err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	return nil
}

//go:embed */*.sql
var sys embed.FS
