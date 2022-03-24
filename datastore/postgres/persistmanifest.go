package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
)

var (
	persistManifestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "persistmanifest_total",
			Help:      "Total number of database queries issued in the PersistManifest method.",
		},
		[]string{"query"},
	)

	persistManifestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "persistmanifest_duration_seconds",
			Help:      "The duration of all queries issued in the PersistManifest method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) PersistManifest(ctx context.Context, manifest claircore.Manifest) error {
	const (
		insertManifest = `
		INSERT INTO manifest (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertLayer = `
		INSERT INTO layer (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertManifestLayer = `
		WITH manifests AS (
			SELECT id AS manifest_id
			FROM manifest
			WHERE hash = $1
		),
			 layers AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE hash = $2
			 )
		INSERT
		INTO manifest_layer (manifest_id, layer_id, i)
		VALUES ((SELECT manifest_id FROM manifests),
				(SELECT layer_id FROM layers),
				$3)
		ON CONFLICT DO NOTHING;
		`
	)

	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = tx.Exec(tctx, insertManifest, manifest.Hash)
	done()
	if err != nil {
		return fmt.Errorf("failed to insert manifest: %w", err)
	}
	persistManifestCounter.WithLabelValues("insertManifest").Add(1)
	persistManifestDuration.WithLabelValues("insertManifest").Observe(time.Since(start).Seconds())

	for i, layer := range manifest.Layers {
		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, err = tx.Exec(tctx, insertLayer, layer.Hash)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert layer: %w", err)
		}
		persistManifestCounter.WithLabelValues("insertLayer").Add(1)
		persistManifestDuration.WithLabelValues("insertLayer").Observe(time.Since(start).Seconds())

		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start = time.Now()
		_, err = tx.Exec(tctx, insertManifestLayer, manifest.Hash, layer.Hash, i)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert manifest -> layer link: %w", err)
		}
		persistManifestCounter.WithLabelValues("insertManifestLayer").Add(1)
		persistManifestDuration.WithLabelValues("insertManifestLayer").Observe(time.Since(start).Seconds())
	}

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}
