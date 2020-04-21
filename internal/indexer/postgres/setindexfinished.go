package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func setScanFinished(ctx context.Context, db *sqlx.DB, sr *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		insertManifestScanned = `
		INSERT INTO scanned_manifest (manifest_hash, scanner_id)
		VALUES ($1, $2);
		`
		upsertIndexReport = `
		INSERT INTO indexreport (manifest_hash, scan_result)
		VALUES ($1, $2)
		ON CONFLICT (manifest_hash) DO UPDATE SET scan_result = excluded.scan_result
		`
	)
	// TODO Use passed-in Context.
	// extract scanner ids from manifest outside of transaction
	scannerIDs := []int64{}

	for _, scnr := range scnrs {
		var scannerID int64
		err := db.Get(&scannerID, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
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

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		_, err := tx.Exec(insertManifestScanned, sr.Hash, id)
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
