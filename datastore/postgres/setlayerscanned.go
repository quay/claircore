package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	setLayerScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setlayerscanned_total",
			Help:      "Total number of database queries issued in the SetLayerScanned method.",
		},
		[]string{"query"},
	)

	setLayerScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setlayerscanned_duration_seconds",
			Help:      "The duration of all queries issued in the SetLayerScanned method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "scanner", vs.Name())
	const query = `
WITH
	layer AS (SELECT id FROM layer WHERE hash = $1)
INSERT
INTO
	scanned_layer (layer_id, scanner_id)
VALUES
	(
		(SELECT id AS layer_id FROM layer),
		$2
	)
ON CONFLICT
	(layer_id, scanner_id)
DO
	NOTHING;
`

	scannerID, err := s.selectScanner(vs)
	if err != nil {
		return err
	}
	start := time.Now()
	if _, err = s.pool.Exec(ctx, query, hash, scannerID); err != nil {
		return fmt.Errorf("error setting layer scanned: %w", err)
	}
	setLayerScannedCounter.WithLabelValues("query").Add(1)
	setLayerScannedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}
