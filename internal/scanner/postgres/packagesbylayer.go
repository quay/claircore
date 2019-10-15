package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"

	"github.com/jmoiron/sqlx"
)

const (
	selectPackage = `SELECT id, name, kind, source, version FROM package WHERE id = $1`
	// find the scanartifacts associated with the layer hash and the scanner id in question, then join the package_id and dist_id.
	// selectPackageAndDistByScanArtifact = `SELECT p.id, p.name, p.kind, p.source, p.version, d.id, d.name, d.version, d.version_code_name, d.version_id, d.arch FROM scanartifact sa INNER JOIN package p ON sa.package_id = p.id INNER JOIN dist d ON sa.dist_id = d.id WHERE sa.layer_hash = $1 AND sa.scanner_id = $2;`
	selectPackagesAndDistByArtifactJoin = `SELECT 
  package.id, 
  package.name, 
  package.kind, 
  package.version, 

  source_package.id,
  source_package.name,
  source_package.kind,
  source_package.version,

  dist.id, 
  dist.name, 
  dist.version, 
  dist.version_code_name, 
  dist.version_id, 
  dist.arch 
FROM 
  scanartifact 
  LEFT JOIN package ON scanartifact.package_id = package.id 
  LEFT JOIN package source_package ON scanartifact.source_id = source_package.id
  LEFT JOIN dist ON scanartifact.dist_id = dist.id 
WHERE 
  scanartifact.layer_hash = '%s' AND scanartifact.scanner_id IN (?);`
)

func packagesByLayer(ctx context.Context, db *sqlx.DB, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Package, error) {
	// TODO Use passed-in Context.
	// get scanner ids
	scannerIDs := []int{}
	for _, scnr := range scnrs {
		var scannerID int
		err := db.Get(&scannerID, scannerIDByNameVersionKind, scnr.Name(), scnr.Version(), scnr.Kind())
		if err != nil {
			return nil, fmt.Errorf("store:packageByLayer failed to retrieve scanner ids for scnr %v: %v", scnr, err)
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	// allocate result array
	var res []*claircore.Package = []*claircore.Package{}

	// rebind see: https://jmoiron.github.io/sqlx/ "in queries" section
	// we need to format this query since an IN query can only have one bindvar. TODO: confirm this
	withHash := fmt.Sprintf(selectPackagesAndDistByArtifactJoin, hash)
	inQuery, args, err := sqlx.In(withHash, scannerIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to bind scannerIDs to query: %v", err)
	}
	inQuery = db.Rebind(inQuery)

	rows, err := db.Queryx(inQuery, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("store:packagesByLayer no packages found for hash %v and scnrs %v", hash, scnrs)
		}
		return nil, fmt.Errorf("store:packagesByLayer failed to retrieve package rows for hash %v and scanners %v: %v", hash, scnrs, err)
	}
	defer rows.Close()

	for rows.Next() {
		var pkg claircore.Package
		var spkg claircore.Package
		var dist claircore.Distribution

		err := rows.Scan(
			&pkg.ID,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,

			&spkg.ID,
			&spkg.Name,
			&spkg.Kind,
			&spkg.Version,

			&dist.ID,
			&dist.Name,
			&dist.Version,
			&dist.VersionCodeName,
			&dist.VersionID,
			&dist.Arch,
		)
		if err != nil {
			return nil, fmt.Errorf("store:packagesByLayer failed to scan packages: %v", err)
		}

		// nest source package
		pkg.Source = &spkg

		res = append(res, &pkg)
	}

	return res, nil
}
