package migrations

import (
	"database/sql"
	"embed"

	"github.com/remind101/migrate"
)

//go:embed *.sql
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

const MigrationTable = "libindex_migrations"

var Migrations = []migrate.Migration{
	{
		ID: 1,
		Up: runFile("01-init.sql"),
	},
	{
		ID: 2,
		Up: runFile("02-digests.sql"),
	},
	{
		ID: 3,
		Up: runFile("03-unique-manifest_index.sql"),
	},
	{
		ID: 4,
		Up: runFile("04-foreign-key-cascades.sql"),
	},
}
