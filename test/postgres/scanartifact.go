package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
)

// InsertScanArtifacts will create ScanArtifacts linking the layer hash, packages, and scnr artifacts.
// if multiple scnrs are provided they will be liked in i % n fashion where i is the current index
// of the Packages array and n is the len of the scnrs array.
func InsertScanArtifacts(db *sqlx.DB, layerHash string, pkgs []*claircore.Package, scnrs scanner.VersionedScanners) error {
	n := len(scnrs)
	for i, pkg := range pkgs {
		nn := i % n
		_, err := db.Exec(`INSERT INTO scanartifact (layer_hash, package_id, dist_id, source_id, scanner_id) VALUES ($1, $2, $3, $4, $5)`,
			&layerHash, &pkg.ID, &pkg.Dist.ID, &pkg.Source.ID, &nn)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
