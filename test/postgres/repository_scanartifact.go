package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func InsertRepoScanArtifact(db *sqlx.DB, layerHash claircore.Digest, repos []*claircore.Repository, scnrs indexer.VersionedScanners) error {
	n := len(scnrs)
	for i, repo := range repos {
		nn := i % n
		_, err := db.Exec(`INSERT INTO repo_scanartifact
			(layer_hash, repo_id, scanner_id)
		VALUES
			($1, $2, $3)`,
			&layerHash, &repo.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert repo scan artifact: %v", err)
		}
	}

	return nil
}
