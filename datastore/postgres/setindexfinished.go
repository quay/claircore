package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	setIndexedFinishedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexedfinished_total",
			Help:      "Total number of database queries issued in the SetIndexFinished method.",
		},
		[]string{"query"},
	)

	setIndexedFinishedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexfinished_duration_seconds",
			Help:      "The duration of all queries issued in the SetIndexFinished method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	const (
		insertManifestScanned = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	scanned_manifest (manifest_id, scanner_id)
VALUES
	((SELECT manifest_id FROM manifests), $2);
`
		upsertIndexReport = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	indexreport (manifest_id, scan_result)
VALUES
	((SELECT manifest_id FROM manifests), $2)
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET scan_result = excluded.scan_result;
`
	)

	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return fmt.Errorf("failed to select package scanner id: %w", err)
	}

	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		tctx, done := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, err := tx.Exec(tctx, insertManifestScanned, ir.Hash, id)
		done()
		if err != nil {
			return fmt.Errorf("failed to link manifest with scanner list: %w", err)
		}
		setIndexedFinishedCounter.WithLabelValues("insertManifestScanned").Add(1)
		setIndexedFinishedDuration.WithLabelValues("insertManifestScanned").Observe(time.Since(start).Seconds())
	}

	// push IndexReport to the store
	// we cast claircore.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = tx.Exec(tctx, upsertIndexReport, ir.Hash, jsonbIndexReport(*ir))
	done()
	if err != nil {
		return fmt.Errorf("failed to upsert scan result: %w", err)
	}
	setIndexedFinishedCounter.WithLabelValues("upsertIndexReport").Add(1)
	setIndexedFinishedDuration.WithLabelValues("upsertIndexReport").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}
