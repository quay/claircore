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
	indexFilesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexfiles_total",
			Help:      "Total number of database queries issued in the IndexFiles method.",
		},
		[]string{"query"},
	)

	indexFilesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexfiles_duration_seconds",
			Help:      "The duration of all queries issued in the IndexFiles method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexFiles(ctx context.Context, files []claircore.File, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		lookupLayerID = `
		SELECT id FROM layer WHERE hash = $1
		`

		lookupScannerID = `
		SELECT id FROM scanner WHERE scanner.name = $1 AND version = $2 AND kind = $3
		`

		insert = `
		INSERT INTO file
			(path, kind)
		VALUES
			($1, $2)
		ON CONFLICT (path, kind) DO NOTHING;
		`

		insertWith = `
		INSERT
		INTO file_scanartifact (file_id, layer_id, scanner_id)
		VALUES (
			(SELECT id FROM file WHERE file.path = $1 AND file.kind = $2),
			$3,
			$4
		)
		ON CONFLICT DO NOTHING;
		`
	)

	var layerID, scannerID int64

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	// Get layerID
	start := time.Now()
	layerRow := tx.QueryRow(ctx, lookupLayerID, layer.Hash)
	err = layerRow.Scan(&layerID)
	if err != nil {
		return fmt.Errorf("failed look up layer ID: %v", err)
	}
	indexFilesCounter.WithLabelValues("lookup_layer").Add(1)
	indexFilesDuration.WithLabelValues("lookup_layer").Observe(time.Since(start).Seconds())

	// Get scannerID
	start = time.Now()
	scannerRow := tx.QueryRow(ctx, lookupScannerID, scnr.Name(), scnr.Version(), scnr.Kind())
	err = scannerRow.Scan(&scannerID)
	if err != nil {
		return fmt.Errorf("failed look up scanner ID: %v", err)
	}
	indexFilesCounter.WithLabelValues("lookup_scanner").Add(1)
	indexFilesDuration.WithLabelValues("lookup_scanner").Observe(time.Since(start).Seconds())

	insertFileStmt, err := tx.Prepare(ctx, "insertFileStmt", insert)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	insertFileScanArtifactWithStmt, err := tx.Prepare(ctx, "insertFileScanArtifactWithStmt", insertWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	start = time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, f := range files {
		err := mBatcher.Queue(
			ctx,
			insertFileStmt.SQL,
			f.Path,
			f.Kind,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for file %v: %w", f, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for file: %w", err)
	}
	indexFilesCounter.WithLabelValues("insert_batch").Add(1)
	indexFilesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	// make file scan artifacts
	start = time.Now()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, f := range files {
		err := mBatcher.Queue(
			ctx,
			insertFileScanArtifactWithStmt.SQL,
			f.Path,
			f.Kind,
			layerID,
			scannerID,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for file_scanartifact %v: %w", f, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for file_scanartifact: %w", err)
	}
	indexFilesCounter.WithLabelValues("insertWith_batch").Add(1)
	indexFilesDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}
