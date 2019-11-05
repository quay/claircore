package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	insertDistribution = `INSERT INTO dist 
		(name, did, version, version_code_name, version_id, arch, cpe) 
	VALUES 
		($1, $2, $3, $4, $5, $6, $7) 
	ON CONFLICT (name, did, version, version_code_name, version_id, arch, cpe) DO NOTHING;`

	insertDistributionScanArtifactWith = `WITH distributions AS (
	SELECT id AS dist_id FROM dist WHERE
         name = $1 AND 
		 did = $2 AND 
		 version = $3 AND
		 version_code_name = $4 AND
		 version_id = $5 AND
		 arch = $6 AND 
		 cpe = $7
         ),

	scanner AS (
	SELECT id AS scanner_id FROM scanner WHERE
	name = $8 AND version = $9 AND kind = $10
		)
	      
INSERT INTO dist_scanartifact (layer_hash, dist_id, scanner_id) VALUES 
		  ($11, 
          (SELECT dist_id FROM distributions),
          (SELECT scanner_id FROM scanner))
          ON CONFLICT DO NOTHING;`
)

func indexDistributions(ctx context.Context, db *sqlx.DB, pool *pgxpool.Pool, dists []*claircore.Distribution, layer *claircore.Layer, scnr scanner.VersionedScanner) error {
	// obtain a transaction scopped batch
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	insertDistStmt, err := tx.Prepare(ctx, "insertDistStmt", insertDistribution)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	insertDistScanArtifactWithStmt, err := tx.Prepare(ctx, "insertDistScanArtifactWith", insertDistributionScanArtifactWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}

	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist %v: %v", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist: %v", err)
	}

	// make dist scan artifacts
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistScanArtifactWithStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist_scanartifact %v: %v", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist_scanartifact: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store:indexDistributions failed to commit tx: %v", err)
	}
	return nil
}
