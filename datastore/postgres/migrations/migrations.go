package migrations

import (
	"database/sql"
	"embed"

	"github.com/remind101/migrate"
)

const (
	IndexerMigrationTable = "libindex_migrations"
	MatcherMigrationTable = "libvuln_migrations"
)

//go:embed */*.sql
var fs embed.FS

func runFile(n string) func(*sql.Tx) error {
	b, err := fs.ReadFile(n)
	return func(tx *sql.Tx) error {
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(b)); err != nil {
			return err
		}
		return nil
	}
}

var IndexerMigrations = []migrate.Migration{
	{
		ID: 1,
		Up: runFile("indexer/01-init.sql"),
	},
	{
		ID: 2,
		Up: runFile("indexer/02-digests.sql"),
	},
	{
		ID: 3,
		Up: runFile("indexer/03-unique-manifest_index.sql"),
	},
	{
		ID: 4,
		Up: runFile("indexer/04-foreign-key-cascades.sql"),
	},
	{
		ID: 5,
		Up: runFile("indexer/05-delete-manifest-index-index.sql"),
	},
	{
		ID: 6,
		Up: runFile("indexer/06-file-artifacts.sql"),
	},
	{
		ID: 7,
		Up: runFile("indexer/07-index-manifest_index.sql"),
	},
}

var MatcherMigrations = []migrate.Migration{
	{
		ID: 1,
		Up: runFile("matcher/01-init.sql"),
	},
	{
		ID: 2,
		Up: runFile("matcher/02-indexes.sql"),
	},
	{
		ID: 3,
		Up: runFile("matcher/03-pyup-fingerprint.sql"),
	},
	{
		ID: 4,
		Up: runFile("matcher/04-enrichments.sql"),
	},
	{
		ID: 5,
		Up: runFile("matcher/05-uo_enrich-fkey.sql"),
	},
	{
		ID: 6,
		Up: runFile("matcher/06-delete-debian-update_operation.sql"),
	},
	{
		ID: 7,
		Up: runFile("matcher/07-force-alpine-update.sql"),
	},
	{
		ID: 8,
		Up: runFile("matcher/08-updater-status.sql"),
	},
	{
		ID: 9,
		Up: runFile("matcher/09-delete-pyupio.sql"),
	},
	{
		ID: 10,
		Up: runFile("matcher/10-delete-osv.sql"),
	},
	{
		ID: 11,
		Up: runFile("matcher/11-add-update_operation-mv.sql"),
	},
	{
		ID: 12,
		Up: runFile("matcher/12-add-latest_update_operation-index.sql"),
	},
	{
		ID: 13,
		Up: runFile("matcher/13-delete-rhel-oval.sql"),
	},
	{
		ID: 14,
		Up: runFile("matcher/14-delete-rhcc-vulns.sql"),
	},
}
