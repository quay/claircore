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
	setIndexReportCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexreport_total",
			Help:      "Total number of database queries issued in the SetIndexReport method.",
		},
		[]string{"query"},
	)

	setIndexReportDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexreport_duration_seconds",
			Help:      "The duration of all queries issued in the SetIndexReport method",
		},
		[]string{"query"},
	)
)

//go:embed sql/set_indexreport.sql
var setIndexReportSQL string

func (s *store) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	// we cast scanner.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations

	ctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	_, err := s.pool.Exec(ctx, setIndexReportSQL, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %w", err)
	}
	setIndexReportCounter.WithLabelValues("query").Add(1)
	setIndexReportDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}
