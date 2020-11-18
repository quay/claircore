package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
)

func setIndexReport(ctx context.Context, db *sqlx.DB, sr *claircore.IndexReport) error {
	const (
		upsertIndexReport = `
		WITH manifests AS (
			SELECT id AS manifest_id
			FROM manifest
			WHERE hash = $1
		)
		INSERT
		INTO indexreport (manifest_id, scan_result)
		VALUES ((select manifest_id from manifests),
				$2)
		ON CONFLICT (manifest_id) DO UPDATE SET scan_result = excluded.scan_result
		`
	)
	// TODO Use passed-in Context.
	// we cast scanner.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations
	_, err := db.Exec(upsertIndexReport, sr.Hash, jsonbIndexReport(*sr))
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %v", err)
	}

	return nil
}
