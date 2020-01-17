package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	insertPackage = `INSERT INTO package (name, kind, version) VALUES ($1, $2, $3) ON CONFLICT (name, kind, version) DO NOTHING;`
	selectDistID  = `SELECT id FROM dist WHERE name = $1 AND version = $2 AND version_code_name = $3 AND version_id = $4 AND arch = $5;`
	// we'll use a WITH statement here to gather all the id's necessary to create the
	// scan artifact entry. see: https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING
	insertPackageScanArtifactWith = `WITH source_package AS (
	SELECT id AS source_id FROM package WHERE
         name = $1 AND kind = $2 AND version = $3
         ),

	binary_package AS (
        SELECT id AS package_id FROM package WHERE 
	name = $4 AND kind = $5 AND version = $6
         ),
        
	scanner AS (
	SELECT id AS scanner_id FROM scanner WHERE
	name = $7 AND version = $8 AND kind = $9
		)
	      
INSERT INTO package_scanartifact (layer_hash, package_db, repository_hint, package_id, source_id, scanner_id) VALUES 
		  ($10, 
           $11,
           $12,
          (SELECT package_id FROM binary_package),
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
func indexPackages(ctx context.Context, db *sqlx.DB, pool *pgxpool.Pool, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/postgres/indexPackages").
		Logger()
	// obtain a transaction scoped batch
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	insertPackageStmt, err := tx.Prepare(ctx, "insertPackageStmt", insertPackage)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	insertPackageScanArtifactWithStmt, err := tx.Prepare(ctx, "insertPackageScanArtifactWith", insertPackageScanArtifactWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}

	skipCt := 0
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
		}
		if pkg.Source != nil {
			err := mBatcher.Queue(
				ctx,
				insertPackageStmt.SQL,
				pkg.Source.Name,
				pkg.Source.Kind,
				pkg.Source.Version,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for pkg %v: %v", pkg, err)
			}
		} else {
			pkg.Source = &claircore.Package{}
			err := mBatcher.Queue(
				ctx,
				insertPackageStmt.SQL,
				pkg.Source.Name,
				pkg.Source.Kind,
				pkg.Source.Version,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for pkg %v: %v", pkg, err)
			}
		}

		err := mBatcher.Queue(
			ctx,
			insertPackageStmt.SQL,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for pkg %v: %v", pkg, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for pkg: %v", err)
	}
	log.Debug().
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("packages inserted")

	skipCt = 0
	// make package scan artifacts
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
			continue
		}
		err := mBatcher.Queue(
			ctx,
			insertPackageScanArtifactWithStmt.SQL,
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
			pkg.PackageDB,
			pkg.RepositoryHint,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package_scanartifact %v: %v", pkg, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for package_scanartifact: %v", err)
	}
	log.Debug().
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("scanartifacts inserted")

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %v", err)
	}
	return nil
}
