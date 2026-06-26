package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// SetIndexPartial persists a degraded index report and marks the manifest as
// scanned to prevent immediate retry loops.
func (s *IndexerStore) SetIndexPartial(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	return s.SetIndexFinished(ctx, ir, scnrs)
}

func (s *IndexerStore) RequeueIndexPartials(ctx context.Context, minAge time.Duration, limit int) (int64, error) {
	if limit < 1 {
		limit = 1
	}
	const query = `
WITH partial_manifests AS (
	SELECT
		ir.manifest_id
	FROM
		indexreport ir
	WHERE
		ir.state = 'IndexPartial'
		AND ir.updated_at <= now() - $1::interval
	ORDER BY
		ir.updated_at ASC,
		ir.manifest_id ASC
	LIMIT $2
),
partial_layers AS (
	SELECT DISTINCT
		ml.layer_id
	FROM
		manifest_layer ml
		JOIN partial_manifests pm ON pm.manifest_id = ml.manifest_id
	WHERE
		NOT EXISTS (
			SELECT
				1
			FROM
				manifest_layer ml2
				LEFT JOIN indexreport ir2 ON ir2.manifest_id = ml2.manifest_id
			WHERE
				ml2.layer_id = ml.layer_id
				AND ml2.manifest_id NOT IN (
					SELECT
						manifest_id
					FROM
						partial_manifests
				)
				AND COALESCE(ir2.state, '') <> 'IndexPartial'
		)
),
deleted_manifest_scans AS (
	DELETE FROM scanned_manifest sm
	USING partial_manifests pm
	WHERE sm.manifest_id = pm.manifest_id
	RETURNING sm.manifest_id
),
deleted_layer_scans AS (
	DELETE FROM scanned_layer sl
	USING partial_layers pl
	WHERE sl.layer_id = pl.layer_id
	RETURNING sl.layer_id
)
UPDATE indexreport ir
SET
	updated_at = now()
FROM partial_manifests pm
WHERE ir.manifest_id = pm.manifest_id;
`
	tag, err := s.pool.Exec(ctx, query, minAge, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to requeue partial index reports: %w", err)
	}
	return tag.RowsAffected(), nil
}
