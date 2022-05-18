package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// InsertPackageScanArtifacts will create ScanArtifacts linking the layer hash,
// packages, and scanner artifacts.
//
// If multiple scanners are provided they will be linked in i % n fashion where
// "i" is the current index of the Packages array and "n" is the length of the
// scanners array.
func InsertPackageScanArtifacts(ctx context.Context, pool *pgxpool.Pool, layerHash claircore.Digest, pkgs []*claircore.Package, scnrs indexer.VersionedScanners) error {
	query := `
INSERT
INTO
	package_scanartifact
		(
			layer_id,
			package_id,
			source_id,
			scanner_id,
			package_db,
			repository_hint
		)
VALUES
	(
		(SELECT id FROM layer WHERE hash = $1),
		$2,
		$3,
		$4,
		$5,
		$6
	);
`
	insertLayer := `
INSERT INTO layer (hash) VALUES ($1);
`

	_, err := pool.Exec(ctx, insertLayer, &layerHash)
	if err != nil {
		return fmt.Errorf("failed to insert layer %v", err)
	}

	n := len(scnrs)
	for i, pkg := range pkgs {
		nn := i % n
		_, err := pool.Exec(ctx, query, &layerHash, &pkg.ID, &pkg.Source.ID, &nn, &pkg.PackageDB, &pkg.RepositoryHint)
		if err != nil {
			return fmt.Errorf("failed to insert scan artifact %v", err)
		}
	}

	return nil
}
