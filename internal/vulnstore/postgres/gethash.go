package postgres

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

const (
	selectHash = `SELECT hash FROM updatecursor WHERE updater = $1`
)

// getHash selects the value at the given key. if not value is present we
// return an empty string
func getHash(db *sqlx.DB, updater string) (string, error) {
	var v sql.NullString
	err := db.Get(&v, selectHash, updater)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}

	if !v.Valid {
		return "", nil
	}
	return v.String, nil
}
