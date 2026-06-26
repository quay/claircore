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

func (s *IndexerStore) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	const query = `
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
	indexreport (manifest_id, state, scan_result, updated_at)
VALUES
	((SELECT manifest_id FROM manifests), $2, $3, now())
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET state = excluded.state,
	scan_result = excluded.scan_result,
	updated_at = excluded.updated_at;
`
	start := time.Now()
	_, err := s.pool.Exec(ctx, query, ir.Hash, ir.State, ir)
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %w", err)
	}
	setIndexReportCounter.WithLabelValues("query").Add(1)
	setIndexReportDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}
