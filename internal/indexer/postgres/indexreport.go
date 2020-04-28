package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
)

const (
	selectIndexReport = `SELECT scan_result FROM indexreport WHERE manifest_hash = $1`
)

func indexReport(ctx context.Context, db *sqlx.DB, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	// TODO Use passed-in Context.
	// we scan into a jsonbIndexReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbIndexReport

	row := db.QueryRow(selectIndexReport, hash)
	err := row.Scan(&jsr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("store:indexReport failed to retrieve index report: %v", err)
	}

	var sr claircore.IndexReport
	sr = claircore.IndexReport(jsr)
	return &sr, true, nil
}
