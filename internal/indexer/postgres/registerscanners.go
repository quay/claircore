package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore/internal/indexer"
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

var (
	//go:embed sql/insert_scanner.sql
	insertScannerSQL string
	//go:embed sql/scanner_exists.sql
	scannerExistsSQL string
)

func (s *store) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	var ok bool
	var err error
	var tctx context.Context
	var done context.CancelFunc
	for _, v := range vs {
		tctx, done = context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err = s.pool.QueryRow(tctx, scannerExistsSQL, v.Name(), v.Version(), v.Kind()).
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
		_, err = s.pool.Exec(tctx, insertScannerSQL, v.Name(), v.Version(), v.Kind())
		done()
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("insert").Add(1)
		registerScannerDuration.WithLabelValues("insert").Observe(time.Since(start).Seconds())
	}

	return nil
}
