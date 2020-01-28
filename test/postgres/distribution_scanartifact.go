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
	n := len(scnrs)
	for i, dist := range dists {
		nn := i % n
		_, err := db.Exec(`INSERT INTO dist_scanartifact (layer_hash, dist_id, scanner_id) VALUES ($1, $2, $3)`,
			&layerHash, &dist.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
