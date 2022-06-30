package postgres

import (
	"context"
	_ "embed"
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

var (
	//go:embed sql/insert_manifest.sql
	insertManifestSQL string
	//go:embed sql/insert_layer.sql
	insertLayerSQL string
	//go:embed sql/insert_manifest_layer.sql
	insertManifestLayerSQL string
)

func (s *store) PersistManifest(ctx context.Context, manifest claircore.Manifest) error {
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = tx.Exec(tctx, insertManifestSQL, manifest.Hash)
	done()
	if err != nil {
		return fmt.Errorf("failed to insert manifest: %w", err)
	}
	persistManifestCounter.WithLabelValues("insertManifest").Add(1)
	persistManifestDuration.WithLabelValues("insertManifest").Observe(time.Since(start).Seconds())

	for i, layer := range manifest.Layers {
		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, err = tx.Exec(tctx, insertLayerSQL, layer.Hash)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert layer: %w", err)
		}
		persistManifestCounter.WithLabelValues("insertLayer").Add(1)
		persistManifestDuration.WithLabelValues("insertLayer").Observe(time.Since(start).Seconds())

		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start = time.Now()
		_, err = tx.Exec(tctx, insertManifestLayerSQL, manifest.Hash, layer.Hash, i)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert manifest → layer link: %w", err)
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
