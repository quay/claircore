package migrations

import (
	"database/sql"
	"embed"

	"github.com/remind101/migrate"
)

const MigrationTable = "libvuln_migrations"

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

var Migrations = []migrate.Migration{
	{
		ID: 1,
		Up: runFile("01-init.sql"),
	},
	{
		ID: 2,
		Up: runFile("02-indexes.sql"),
	},
	{
		ID: 3,
		Up: runFile("03-pyup-fingerprint.sql"),
	},
	{
		ID: 4,
		Up: runFile("04-enrichments.sql"),
	},
	{
		ID: 5,
		Up: runFile("05-uo_enrich-fkey.sql"),
	},
	{
		ID: 6,
		Up: runFile("06-delete-debian-update_operation.sql"),
	},
	{
<<<<<<< HEAD
		ID: 7,
		Up: runFile("07-force-alpine-update.sql"),
=======
		ID: 6,
		Up: func(tx *sql.Tx) error {
			_, err := tx.Exec(migration6)
			return err
		},
>>>>>>> 68834dd (updates: Record in a new table each time updaters check for vulns)
	},
}
