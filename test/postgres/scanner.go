package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore/internal/indexer"
)

// InsertUniqueScanners inserts each unique scanner into the database. the scanner's primary key (int) is set
// to the index of the scanner in the array.
func InsertUniqueScanners(db *sqlx.DB, scnrs indexer.VersionedScanners) error {
	for i, scnr := range scnrs {
		_, err := db.Exec(`INSERT INTO scanner (id, kind, name, version) VALUES ($1, $2, $3, $4);`, i, scnr.Kind(), scnr.Name(), scnr.Version())
		if err != nil {
			return fmt.Errorf("failed to insert test scanner: %v", err)
		}
	}
	return nil
}
