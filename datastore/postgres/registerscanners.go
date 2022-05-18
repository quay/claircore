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
	var tctx context.Context
	var done context.CancelFunc
	for _, v := range vs {
		tctx, done = context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err = s.pool.QueryRow(tctx, exists, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		done()
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("exists").Add(1)
		registerScannerDuration.WithLabelValues("exists").Observe(time.Since(start).Seconds())
		if ok {
			continue
		}

		tctx, done = context.WithTimeout(ctx, time.Second)
		start = time.Now()
		_, err = s.pool.Exec(tctx, insert, v.Name(), v.Version(), v.Kind())
		done()
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("insert").Add(1)
		registerScannerDuration.WithLabelValues("insert").Observe(time.Since(start).Seconds())
	}

	return nil
}
