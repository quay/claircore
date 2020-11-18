package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// InsertDistScanArtifacts will create DistributionScanArtifacts linking the layer hash, dists, and scnr artifacts.
// if multiple scnrs are provided they will be liked in i % n fashion where i is the current index
// of the Dists array and n is the len of the scnrs array.
func InsertDistScanArtifacts(db *sqlx.DB, layerHash claircore.Digest, dists []*claircore.Distribution, scnrs indexer.VersionedScanners) error {
	query := `
	WITH layer_insert AS (
		INSERT INTO layer (hash)
			VALUES ($1)
			ON CONFLICT (hash) DO UPDATE SET hash=$1
			RETURNING id AS layer_id
	)
	INSERT INTO dist_scanartifact (layer_id, dist_id, scanner_id) VALUES ((SELECT layer_id FROM layer_insert),
																		  $2,
																		  $3)
	`

	insertLayer := `
	INSERT INTO layer (hash)
	VALUES ($1);
	`

	_, err := db.Exec(insertLayer, &layerHash)
	if err != nil {
		return fmt.Errorf("failed to insert layer %v", err)
	}

	n := len(scnrs)
	for i, dist := range dists {
		nn := i % n
		_, err := db.Exec(query,
			&layerHash, &dist.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
