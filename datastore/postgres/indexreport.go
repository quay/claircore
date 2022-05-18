package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
)

var (
	indexReportCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexreport_total",
			Help:      "Total number of database queries issued in the IndexReport method.",
		},
		[]string{"query"},
	)

	indexReportDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexreport_duration_seconds",
			Help:      "The duration of all queries issued in the IndexReport method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	const query = `
	SELECT scan_result
	FROM indexreport
			 JOIN manifest ON manifest.hash = $1
	WHERE indexreport.manifest_id = manifest.id;
	`
	// we scan into a jsonbIndexReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbIndexReport

	ctx, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	start := time.Now()
	err := s.pool.QueryRow(ctx, query, hash).Scan(&jsr)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("failed to retrieve index report: %w", err)
	}
	indexReportCounter.WithLabelValues("query").Add(1)
	indexReportDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	sr := claircore.IndexReport(jsr)
	return &sr, true, nil
}
