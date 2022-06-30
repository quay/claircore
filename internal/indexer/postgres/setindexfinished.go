package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
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
			Help:      "Duration of all queries issued in the SetIndexFinished method.",
		},
		[]string{"query"},
	)
)

var (
	//go:embed sql/insert_manifest_scanned.sql
	insertManifestScannedSQL string
	//go:embed sql/upsert_indexreport.sql
	upsertIndexReportSQL string
)

func (s *store) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
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
		_, err := tx.Exec(tctx, insertManifestScannedSQL, ir.Hash, id)
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
	_, err = tx.Exec(tctx, upsertIndexReportSQL, ir.Hash, jsonbIndexReport(*ir))
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
