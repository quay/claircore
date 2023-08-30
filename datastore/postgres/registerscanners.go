package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore/indexer"
)

var (
	registerScannerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_total",
			Help:      "Total number of database queries issued in the RegiterScanners method.",
		},
		[]string{"query"},
	)

	registerScannerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_duration_seconds",
			Help:      "The duration of all queries issued in the RegiterScanners method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	const (
		insert = `
INSERT
INTO
	scanner (name, version, kind)
VALUES
	($1, $2, $3)
ON CONFLICT
	(name, version, kind)
DO
	NOTHING;
`
		exists = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			scanner
		WHERE
			name = $1 AND version = $2 AND kind = $3
	);
`
	)

	var ok bool
	var err error
	for _, v := range vs {
		start := time.Now()
		err = s.pool.QueryRow(ctx, exists, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("exists").Add(1)
		registerScannerDuration.WithLabelValues("exists").Observe(time.Since(start).Seconds())
		if ok {
			continue
		}

		start = time.Now()
		_, err = s.pool.Exec(ctx, insert, v.Name(), v.Version(), v.Kind())
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("insert").Add(1)
		registerScannerDuration.WithLabelValues("insert").Observe(time.Since(start).Seconds())
	}

	return nil
}
