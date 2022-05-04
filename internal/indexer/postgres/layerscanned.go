package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	layerScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "layerscanned_total",
			Help:      "Total number of database queries issued in the LayerScanned method.",
		},
		[]string{"query"},
	)

	layerScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "layerscanned_duration_seconds",
			Help:      "The duration of all queries issued in the LayerScanned method",
		},
		[]string{"query"},
	)
)

//go:embed sql/select_scanned.sql
var selectScannedSQL string

func (s *store) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	// TODO(hank) Could this be written as a single query that reports NULL if
	// the scanner isn't present?
	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	start := time.Now()
	var scannerID int64
	err := s.pool.QueryRow(ctx, selectScannerSQL, scnr.Name(), scnr.Version(), scnr.Kind()).
		Scan(&scannerID)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("scanner %q not found", scnr)
	default:
		return false, err
	}
	layerScannedCounter.WithLabelValues("selectScanner").Add(1)
	layerScannedDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())

	var ok bool

	start = time.Now()
	err = s.pool.QueryRow(ctx, selectScannedSQL, hash.String(), scannerID).
		Scan(&ok)
	if err != nil {
		return false, err
	}
	layerScannedCounter.WithLabelValues("selectScanned").Add(1)
	layerScannedDuration.WithLabelValues("selectScanned").Observe(time.Since(start).Seconds())

	return ok, nil
}
