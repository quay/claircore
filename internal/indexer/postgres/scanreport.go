package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/quay/claircore"

	"github.com/jmoiron/sqlx"
)

const (
	selectScanReport = `SELECT scan_result FROM scanreport WHERE manifest_hash = $1`
)

func scanReport(ctx context.Context, db *sqlx.DB, hash string) (*claircore.ScanReport, bool, error) {
	// TODO Use passed-in Context.
	// we scan into a jsonbScanReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbScanReport

	row := db.QueryRow(selectScanReport, hash)
	err := row.Scan(&jsr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("store:scanReport failed to retrieve scanResult: %v", err)
	}

	var sr claircore.ScanReport
	sr = claircore.ScanReport(jsr)
	return &sr, true, nil
}
