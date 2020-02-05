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
	n := len(scnrs)
	for i, pkg := range pkgs {
		nn := i % n
		_, err := db.Exec(`INSERT INTO package_scanartifact (layer_hash, package_id, source_id, scanner_id, package_db, repository_hint) VALUES ($1, $2, $3, $4, $5, $6)`,
			&layerHash, &pkg.ID, &pkg.Source.ID, &nn, &pkg.PackageDB, &pkg.RepositoryHint)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
