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
		INSERT INTO indexreport (manifest_hash, scan_result)
		VALUES ($1, $2)
		ON CONFLICT (manifest_hash) DO UPDATE SET scan_result = excluded.scan_result
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
