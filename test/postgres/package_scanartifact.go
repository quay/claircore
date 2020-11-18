package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// InsertPackageScanArtifacts will create ScanArtifacts linking the layer hash, packages, and scnr artifacts.
// if multiple scnrs are provided they will be liked in i % n fashion where i is the current index
// of the Packages array and n is the len of the scnrs array.
func InsertPackageScanArtifacts(db *sqlx.DB, layerHash claircore.Digest, pkgs []*claircore.Package, scnrs indexer.VersionedScanners) error {
	query := `
	INSERT
	INTO package_scanartifact (layer_id, package_id, source_id, scanner_id, package_db, repository_hint)
	VALUES ((SELECT id FROM layer WHERE hash = $1),
			$2,
			$3,
			$4,
			$5,
			$6)
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
	for i, pkg := range pkgs {
		nn := i % n
		_, err := db.Exec(query,
			&layerHash, &pkg.ID, &pkg.Source.ID, &nn, &pkg.PackageDB, &pkg.RepositoryHint)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
