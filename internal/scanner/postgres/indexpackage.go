package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
)

const (
	insertPackage      = `INSERT INTO package (name, kind, version) VALUES ($1, $2, $3) ON CONFLICT (name, kind, version) DO NOTHING;`
	insertDistribution = `INSERT INTO dist (name, version, version_code_name, version_id, arch) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (name, version, version_code_name, version_id, arch) DO NOTHING;`
	insertScanArtifact = `INSERT INTO scanartifact (layer_hash, kind, package_id, dist_id, scanner_id) VALUES ($1, $2, $3, $4, $5);`
	selectPackageID    = `SELECT id FROM package WHERE name = $1 AND kind = $2 AND version = $3;`
	selectDistID       = `SELECT id FROM dist WHERE name = $1 AND version = $2 AND version_code_name = $3 AND version_id = $4 AND arch = $5;`
	// we'll use a WITH statement here to gather all the id's necessary to create the
	// scan artifact entry. see: https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING
	insertScanArtifactWith = `WITH source_package AS (
	SELECT id AS source_id FROM package WHERE
         name = $1 AND kind = $2 AND version = $3
         ),

	binary_package AS (
        SELECT id AS package_id FROM package WHERE 
	name = $4 AND kind = $5 AND version = $6
         ),

	distribution AS (
	SELECT id AS dist_id FROM dist WHERE 
	name = $7 AND version = $8 AND version_code_name = $9 AND version_id = $10 AND arch = $11
        ),
        
	scanner AS (
	SELECT id AS scanner_id FROM scanner WHERE
	name = $12 AND version = $13 AND kind = $14
		)
	      
INSERT INTO scanartifact (layer_hash, kind, package_id, dist_id, source_id, scanner_id) VALUES 
		  ($15, 
           $16, 
          (SELECT package_id FROM binary_package),
          (SELECT dist_id FROM distribution),
          (SELECT source_id FROM source_package),
          (SELECT scanner_id FROM scanner))
          ON CONFLICT DO NOTHING;`
)

// indexPackages indexes all provides packages along with creating a scan artifact. if a source package is nested
// inside a binary package we index the source package first and then create a relation between the binary package
// and source package.
//
// scan artifacts are used to determine if a particular layer has been scanned by a
// particular scnr. see layerScanned method for more details.
func indexPackages(db *sqlx.DB, pool *pgx.ConnPool, pkgs []*claircore.Package, layer *claircore.Layer, scnr scanner.VersionedScanner) error {

	// obtain a transaction scopped batch
	tx, err := pool.Begin()
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %v", err)
	}

	insertPackageStmt, err := tx.Prepare("insertPackageStmt", insertPackage)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	insertDistributionStmt, err := tx.Prepare("insertDistStmt", insertDistribution)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	insertScanArtifactWithStmt, err := tx.Prepare("insertScanArtifactWith", insertScanArtifactWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}

	batch := tx.BeginBatch()
	// index all nested elements, use zero value structs to enforce unique constraint since
	// postgres does not view "null" as a unique field
	for _, pkg := range pkgs {
		if pkg.Source != nil {
			batch.Queue(
				insertPackageStmt.Name,
				[]interface{}{pkg.Source.Name, pkg.Source.Kind, pkg.Source.Version},
				nil,
				nil,
			)
		} else {
			pkg.Source = &claircore.Package{}
			batch.Queue(
				insertPackageStmt.Name,
				[]interface{}{pkg.Source.Name, pkg.Source.Kind, pkg.Source.Version},
				nil,
				nil,
			)
		}

		if pkg.Dist != nil {
			batch.Queue(
				insertDistributionStmt.Name,
				[]interface{}{pkg.Dist.Name, pkg.Dist.Version, pkg.Dist.VersionCodeName, pkg.Dist.VersionID, pkg.Dist.Arch},
				nil,
				nil,
			)
		} else {
			pkg.Dist = &claircore.Distribution{}
			batch.Queue(
				insertDistributionStmt.Name,
				[]interface{}{pkg.Dist.Name, pkg.Dist.Version, pkg.Dist.VersionCodeName, pkg.Dist.VersionID, pkg.Dist.Arch},
				nil,
				nil,
			)
		}

		batch.Queue(
			insertPackageStmt.Name,
			[]interface{}{pkg.Name, pkg.Kind, pkg.Version},
			nil,
			nil,
		)
	}

	// allow up to 30 seconds for batch.Send() to complete. see warning:
	// https://godoc.org/github.com/jackc/pgx#Batch.Send
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = batch.Send(ctx, nil)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("store:indexPackages fail to batch insert source packages: %v", err)
	}
	batch.Close()

	batch = tx.BeginBatch()
	// create all scan artifacts
	for _, pkg := range pkgs {
		batch.Queue(
			insertScanArtifactWithStmt.Name,
			[]interface{}{
				pkg.Source.Name,
				pkg.Source.Kind,
				pkg.Source.Version,
				pkg.Name,
				pkg.Kind,
				pkg.Version,
				pkg.Dist.Name,
				pkg.Dist.Version,
				pkg.Dist.VersionCodeName,
				pkg.Dist.VersionID,
				pkg.Dist.Arch,
				scnr.Name(),
				scnr.Version(),
				scnr.Kind(),
				layer.Hash,
				"package",
			},
			nil,
			nil,
		)
	}

	// allow up to 30 seconds for batch.Send() to complete. see warning:
	// https://godoc.org/github.com/jackc/pgx#Batch.Send
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = batch.Send(ctx, nil)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("store:indexPackages fail to batch insert scanartifact: %v", err)
	}

	err = batch.Close()
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to close batch: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %v", err)
	}
	return nil
}
