package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// InsertDistScanArtifacts will create DistributionScanArtifacts linking the
// layer hash, dist, and scanner artifacts.
//
// If multiple scanners are provided they will be linked in i % n fashion where
// "i" is the current index of the dists slice and "n" is the length of the
// scnrs slice.
func InsertDistScanArtifacts(ctx context.Context, pool *pgxpool.Pool, layerHash claircore.Digest, dists []*claircore.Distribution, scnrs indexer.VersionedScanners) error {
	query := `
WITH
	layer_insert
		AS (
			INSERT
			INTO
				layer (hash)
			VALUES
				($1)
			ON CONFLICT
				(hash)
			DO
				UPDATE SET hash = $1
			RETURNING
				id AS layer_id
		)
INSERT
INTO
	dist_scanartifact (layer_id, dist_id, scanner_id)
VALUES
	((SELECT layer_id FROM layer_insert), $2, $3);
`

	insertLayer := `
INSERT INTO layer (hash) VALUES ($1);
`

	_, err := pool.Exec(ctx, insertLayer, &layerHash)
	if err != nil {
		return fmt.Errorf("failed to insert layer %v", err)
	}

	n := len(scnrs)
	for i, dist := range dists {
		nn := i % n
		_, err := pool.Exec(ctx, query, &layerHash, &dist.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
