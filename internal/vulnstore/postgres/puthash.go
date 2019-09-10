package postgres

import "github.com/jmoiron/sqlx"

const (
	upsertHash = `INSERT INTO updatecursor (updater, hash) 
				  VALUES 
					($1, $2) 
				  ON CONFLICT (updater) 
				  DO UPDATE SET hash = EXCLUDED.hash;`
)

func putHash(db *sqlx.DB, updater string, hash string) error {
	_, err := db.Exec(upsertHash, updater, hash)
	return err
}
