package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

func InsertRepoScanArtifact(ctx context.Context, pool *pgxpool.Pool, layerHash claircore.Digest, repos []*claircore.Repository, scnrs indexer.VersionedScanners) error {
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
			DO
				UPDATE SET hash = excluded.hash
			RETURNING
				id AS layer_id
		)
INSERT
INTO
	repo_scanartifact (layer_id, repo_id, scanner_id)
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
	for i, repo := range repos {
		nn := i % n
		_, err := pool.Exec(ctx, query, &layerHash, &repo.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert repo scan artifact: %v", err)
		}
	}

	return nil
}
