package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
)

func (s *store) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	const query = `
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
	// we cast scanner.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations
	_, err := s.pool.Exec(ctx, query, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %v", err)
	}

	return nil
}
