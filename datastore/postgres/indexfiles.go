package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
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

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var layerID, scannerID int64
		var batch pgx.Batch
		var start time.Time
		var err error

		start = time.Now()
		err = tx.QueryRow(ctx, lookupLayerID, layer.Hash).Scan(&layerID)
		if err != nil {
			return fmt.Errorf("failed look up layer ID: %v", err)
		}
		indexFilesCounter.WithLabelValues("lookup_layer").Add(1)
		indexFilesDuration.WithLabelValues("lookup_layer").Observe(time.Since(start).Seconds())

		start = time.Now()
		err = tx.QueryRow(ctx, lookupScannerID, scnr.Name(), scnr.Version(), scnr.Kind()).Scan(&scannerID)
		if err != nil {
			return fmt.Errorf("failed look up scanner ID: %v", err)
		}
		indexFilesCounter.WithLabelValues("lookup_scanner").Add(1)
		indexFilesDuration.WithLabelValues("lookup_scanner").Observe(time.Since(start).Seconds())

		start = time.Now()
		for _, f := range files {
			batch.Queue(insert, f.Path, f.Kind)
		}
		err = tx.SendBatch(ctx, &batch).Close()
		if err != nil {
			return fmt.Errorf("batch insert failed for file: %w", err)
		}
		indexFilesCounter.WithLabelValues("insert_batch").Add(1)
		indexFilesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

		clear(batch.QueuedQueries)
		batch.QueuedQueries = batch.QueuedQueries[:0]

		start = time.Now()
		for _, f := range files {
			batch.Queue(insertWith, f.Path, f.Kind, layerID, scannerID)
		}
		err = tx.SendBatch(ctx, &batch).Close()
		if err != nil {
			return fmt.Errorf("batch insert failed for file_scanartifact: %w", err)
		}
		indexFilesCounter.WithLabelValues("insertWith_batch").Add(1)
		indexFilesDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

		return nil
	})
	if err != nil {
		return fmt.Errorf("IndexFiles failed: %w", err)
	}

	return nil
}
