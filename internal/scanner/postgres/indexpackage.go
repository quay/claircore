package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
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
func indexPackages(ctx context.Context, db *sqlx.DB, pool *pgxpool.Pool, pkgs []*claircore.Package, layer *claircore.Layer, scnr scanner.VersionedScanner) error {
	// obtain a transaction scopped batch
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	insertPackageStmt, err := tx.Prepare(ctx, "insertPackageStmt", insertPackage)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	insertScanArtifactWithStmt, err := tx.Prepare(ctx, "insertScanArtifactWith", insertScanArtifactWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}

	batch := &pgx.Batch{}
	// index all nested elements, use zero value structs to enforce unique constraint since
	// postgres does not view "null" as a unique field
	for _, pkg := range pkgs {
		if pkg.Source != nil {
			batch.Queue(
				insertPackageStmt.Name,
				pkg.Source.Name, pkg.Source.Kind, pkg.Source.Version,
			)
		} else {
			pkg.Source = &claircore.Package{}
			batch.Queue(
				insertPackageStmt.Name,
				pkg.Source.Name, pkg.Source.Kind, pkg.Source.Version,
			)
		}

		batch.Queue(
			insertPackageStmt.Name,
			pkg.Name, pkg.Kind, pkg.Version,
		)
	}

	// allow up to 30 seconds for batch.Send() to complete. see warning:
	// https://godoc.org/github.com/jackc/pgx#Batch.Send
	tctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := tx.SendBatch(tctx, batch)
	for i, lim := 0, len(pkgs)*3; i < lim; i++ {
		if _, err := res.Exec(); err != nil {
			res.Close()
			return fmt.Errorf("batch insert failed: %v", err)
		}
	}
	if err := res.Close(); err != nil {
		return fmt.Errorf("store: indexPackage failed to close batch: %v", err)
	}

	batch = &pgx.Batch{}
	// create all scan artifacts
	for _, pkg := range pkgs {
		batch.Queue(
			insertScanArtifactWithStmt.Name,
			pkg.Source.Name,
			pkg.Source.Kind,
			pkg.Source.Version,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
			"package",
		)
	}

	// allow up to 30 seconds for batch.Send() to complete. see warning:
	// https://godoc.org/github.com/jackc/pgx#Batch.Send
	tctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res = tx.SendBatch(tctx, batch)
	for i, lim := 0, len(pkgs); i < lim; i++ {
		if _, err := res.Exec(); err != nil {
			res.Close()
			return fmt.Errorf("store:indexPackages fail to batch insert scanartifact: %v", err)
		}
	}
	if err := res.Close(); err != nil {
		return fmt.Errorf("store:indexPackage failed to close batch: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %v", err)
	}
	return nil
}
