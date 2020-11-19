package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func (s *store) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	const (
		insertManifestScanned = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	scanned_manifest (manifest_id, scanner_id)
VALUES
	((SELECT manifest_id FROM manifests), $2);
`
		upsertIndexReport = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	indexreport (manifest_id, scan_result)
VALUES
	((SELECT manifest_id FROM manifests), $2)
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET scan_result = excluded.scan_result;
`
	)

	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return fmt.Errorf("store:storeManifest failed to select package scanner id: %v", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:setScannerList failed to create transaction for hash %v: %v", ir.Hash, err)
	}
	defer tx.Rollback(ctx)

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		_, err := tx.Exec(ctx, insertManifestScanned, ir.Hash, id)
		if err != nil {
			return fmt.Errorf("store:storeManifest failed to link manifest with scanner list: %v", err)
		}
	}

	// push IndexReport to the store
	// we cast claircore.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations
	_, err = tx.Exec(ctx, upsertIndexReport, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert scan result: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return nil
}
