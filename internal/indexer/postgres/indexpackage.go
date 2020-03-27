package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	insertPackage = `INSERT INTO package (name, kind, version, norm_kind, norm_version, module)
	VALUES ($1, $2, $3, $4, $5::int[], $6)
	ON CONFLICT (name, kind, version, module) DO NOTHING;`
	selectDistID = `SELECT id FROM dist WHERE name = $1 AND version = $2 AND version_code_name = $3 AND version_id = $4 AND arch = $5;`
	// we'll use a WITH statement here to gather all the id's necessary to create the
	// scan artifact entry. see: https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING
	insertPackageScanArtifactWith = `WITH source_package AS (
	SELECT id AS source_id FROM package WHERE
         name = $1 AND kind = $2 AND version = $3 AND module = $4
         ),

	binary_package AS (
        SELECT id AS package_id FROM package WHERE
	name = $5 AND kind = $6 AND version = $7 AND module = $8
         ),

	scanner AS (
	SELECT id AS scanner_id FROM scanner WHERE
	name = $9 AND version = $10 AND kind = $11
		)

INSERT INTO package_scanartifact (layer_hash, package_db, repository_hint, package_id, source_id, scanner_id) VALUES
		  ($12,
           $13,
           $14,
          (SELECT package_id FROM binary_package),
          (SELECT source_id FROM source_package),
          (SELECT scanner_id FROM scanner))
          ON CONFLICT DO NOTHING;`
)

var zeroPackage = claircore.Package{}

// indexPackages indexes all provides packages along with creating a scan artifact. if a source package is nested
// inside a binary package we index the source package first and then create a relation between the binary package
// and source package.
//
// scan artifacts are used to determine if a particular layer has been scanned by a
// particular scnr. see layerScanned method for more details.
func indexPackages(ctx context.Context, pool *pgxpool.Pool, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
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
		if pkg.Source == nil {
			pkg.Source = &zeroPackage
		}

		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg.Source); err != nil {
			return err
		}
		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg); err != nil {
			return err
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
			pkg.Source.Module,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			pkg.Module,
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

func queueInsert(ctx context.Context, b *microbatch.Insert, stmt string, pkg *claircore.Package) error {
	var vKind *string
	var vNorm []int32
	if pkg.NormalizedVersion.Kind != "" {
		vKind = &pkg.NormalizedVersion.Kind
		vNorm = pkg.NormalizedVersion.V[:]
	}
	err := b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, vKind, vNorm, pkg.Module,
	)
	if err != nil {
		return fmt.Errorf("failed to queue insert for package %q: %w", pkg.Name, err)
	}
	return nil
}
