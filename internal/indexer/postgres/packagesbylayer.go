package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/jackc/pgtype"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func packagesByLayer(ctx context.Context, db *sqlx.DB, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Package, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		SELECT package.id,
			   package.name,
			   package.kind,
			   package.version,
			   package.norm_kind,
			   package.norm_version,
			   package.module,
			   package.arch,

			   source_package.id,
			   source_package.name,
			   source_package.kind,
			   source_package.version,
			   source_package.module,
			   source_package.arch,

			   package_scanartifact.package_db,
			   package_scanartifact.repository_hint
		FROM package_scanartifact
				 LEFT JOIN package ON package_scanartifact.package_id = package.id
				 LEFT JOIN package source_package ON package_scanartifact.source_id = source_package.id
		WHERE package_scanartifact.layer_hash = '%s'
		  AND package_scanartifact.scanner_id IN (?);
		`
	)

	if len(scnrs) == 0 {
		return []*claircore.Package{}, nil
	}
	// get scanner ids
	scannerIDs := []int64{}
	for _, scnr := range scnrs {
		var scannerID int64
		err := db.Get(&scannerID, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
		if err != nil {
			return nil, fmt.Errorf("store:packageByLayer failed to retrieve scanner ids for scnr %v: %v", scnr, err)
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	// allocate result array
	var res []*claircore.Package = []*claircore.Package{}

	// rebind see: https://jmoiron.github.io/sqlx/ "in queries" section
	// we need to format this query since an IN query can only have one bindvar. TODO: confirm this
	withHash := fmt.Sprintf(query, hash)
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

		var id int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,

			&spkg.ID,
			&spkg.Name,
			&spkg.Kind,
			&spkg.Version,
			&spkg.Module,
			&spkg.Arch,

			&pkg.PackageDB,
			&pkg.RepositoryHint,
		)
		pkg.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("store:packagesByLayer failed to scan packages: %v", err)
		}
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
		// nest source package
		pkg.Source = &spkg

		res = append(res, &pkg)
	}

	return res, nil
}
