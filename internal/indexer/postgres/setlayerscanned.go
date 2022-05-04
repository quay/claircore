package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
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
			Help:      "Duration of all queries issued in the SetLayerScanned method.",
		},
		[]string{"query"},
	)
)

//go:embed sql/set_layer_scanned.sql
var setLayerScannedSQL string

func (s *store) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "scanner", vs.Name())

	ctx, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	start := time.Now()
	_, err := s.pool.Exec(ctx, setLayerScannedSQL, hash, vs.Name(), vs.Version(), vs.Kind())
	if err != nil {
		return fmt.Errorf("error setting layer scanned: %w", err)
	}
	setLayerScannedCounter.WithLabelValues("query").Add(1)
	setLayerScannedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}
