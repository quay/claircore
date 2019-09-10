package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
)

const (
	upsertScanReport = `INSERT INTO scanreport (manifest_hash, scan_result) VALUES ($1, $2) ON CONFLICT (manifest_hash) DO UPDATE SET scan_result = excluded.scan_result`
)

func setScanReport(db *sqlx.DB, sr *claircore.ScanReport) error {
	// we cast scanner.ScanReport to jsonbScanReport in order to obtain the value/scan
	// implementations
	_, err := db.Exec(upsertScanReport, sr.Hash, jsonbScanReport(*sr))
	if err != nil {
		return fmt.Errorf("failed to upsert scan result: %v", err)
	}

	return nil
}
