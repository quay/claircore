package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const (
	deleteScannerList          = `DELETE FROM scannerlist WHERE manifest_hash = $1;`
	insertScannerList          = `INSERT INTO scannerlist (manifest_hash, scanner_id) VALUES ($1, $2);`
	scannerIDByNameVersionKind = `SELECT id FROM scanner WHERE name = $1 AND version = $2 AND kind = $3;`
)

func setScanFinished(ctx context.Context, db *sqlx.DB, sr *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	// TODO Use passed-in Context.
	// extract scanner ids from manifest outside of transaction
	scannerIDs := []int64{}

	for _, scnr := range scnrs {
		var scannerID int64
		err := db.Get(&scannerID, scannerIDByNameVersionKind, scnr.Name(), scnr.Version(), scnr.Kind())
		if err != nil {
			return fmt.Errorf("store:storeManifest failed to select package scanner id: %v", err)
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	// begin transcation
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store:setScannerList failed to create transaction for hash %v: %v", sr.Hash, err)
	}

	// remove existing scanner list entries if they exist
	_, err = tx.Exec(deleteScannerList, sr.Hash)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("store:storeManifest failed to unlink scanner list: %v", err)
	}

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		_, err := tx.Exec(insertScannerList, sr.Hash, id)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("store:storeManifest failed to link manifest with scanner list: %v", err)
		}
	}

	// push IndexReport to the store
	// we cast claircore.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations
	_, err = tx.Exec(upsertIndexReport, sr.Hash, jsonbIndexReport(*sr))
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to upsert scan result: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}
