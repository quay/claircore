package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/microbatch"
)

var (
	indexDistributionsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_total",
			Help:      "Total number of database queries issued in the IndexDistributions method.",
		},
		[]string{"query"},
	)

	indexDistributionsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_duration_seconds",
			Help:      "The duration of all queries issued in the IndexDistributions method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		insert = `
		INSERT INTO dist 
			(name, did, version, version_code_name, version_id, arch, cpe, pretty_name) 
		VALUES 
			($1, $2, $3, $4, $5, $6, $7, $8) 
		ON CONFLICT (name, did, version, version_code_name, version_id, arch, cpe, pretty_name) DO NOTHING;
		`

		insertWith = `
		WITH distributions AS (
			SELECT id AS dist_id
			FROM dist
			WHERE name = $1
			  AND did = $2
			  AND version = $3
			  AND version_code_name = $4
			  AND version_id = $5
			  AND arch = $6
			  AND cpe = $7
			  AND pretty_name = $8
		),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $9
				   AND version = $10
				   AND kind = $11
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $12
			 )
		INSERT
		INTO dist_scanartifact (layer_id, dist_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT dist_id FROM distributions),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)

	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertDistStmt, err := tx.Prepare(tctx, "insertDistStmt", insert)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertDistScanArtifactWithStmt, err := tx.Prepare(tctx, "insertDistScanArtifactWith", insertWith)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	start := time.Now()
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
			dist.PrettyName,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist: %w", err)
	}
	indexDistributionsCounter.WithLabelValues("insert_batch").Add(1)
	indexDistributionsDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	// make dist scan artifacts
	start = time.Now()
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
			dist.PrettyName,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist_scanartifact %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist_scanartifact: %w", err)
	}
	indexDistributionsCounter.WithLabelValues("insertWith_batch").Add(1)
	indexDistributionsDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to commit tx: %w", err)
	}
	return nil
}
