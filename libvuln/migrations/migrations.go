package migrations

import (
	"database/sql"

	"github.com/remind101/migrate"
)

const (
	MigrationTable = "libvuln_migrations"
)

var Migrations = []migrate.Migration{
	{
		ID: 1,
		Up: func(tx *sql.Tx) error {
			_, err := tx.Exec(migration1)
			return err
		},
	},
}
