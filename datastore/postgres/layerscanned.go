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
	"github.com/quay/claircore/indexer"
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

func (s *IndexerStore) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	// TODO(hank) Could this be written as a single query that reports NULL if
	// the scanner isn't present?
	const (
		selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`
		selectScanned = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			layer
			JOIN scanned_layer ON
					scanned_layer.layer_id = layer.id
		WHERE
			layer.hash = $1
			AND scanned_layer.scanner_id = $2
	);
`
	)

	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	start := time.Now()
	var scannerID int64
	err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
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
	err = s.pool.QueryRow(ctx, selectScanned, hash.String(), scannerID).
		Scan(&ok)
	if err != nil {
		return false, err
	}
	layerScannedCounter.WithLabelValues("selectScanned").Add(1)
	layerScannedDuration.WithLabelValues("selectScanned").Observe(time.Since(start).Seconds())

	return ok, nil
}
