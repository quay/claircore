package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	manifestScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "manifestscanned_total",
			Help:      "Total number of database queries issued in the ManifestScanned method.",
		},
		[]string{"query"},
	)

	manifestScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "manifestscanned_duration_seconds",
			Help:      "The duration of all queries issued in the ManifestScanned method",
		},
		[]string{"query"},
	)
)

// ManifestScanned determines if a manifest has been scanned by ALL the provided
// scanners.
func (s *IndexerStore) ManifestScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (bool, error) {
	const (
		selectScanned = `
		SELECT scanner_id
		FROM scanned_manifest
				 JOIN manifest ON scanned_manifest.manifest_id = manifest.id
		WHERE manifest.hash = $1;
		`
	)

	// get the ids of the scanners we are testing for.
	expectedIDs, err := s.selectScanners(ctx, vs)
	if err != nil {
		return false, err
	}

	// get a map of the found ids which have scanned this package
	foundIDs := map[int64]struct{}{}

	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, selectScanned, hash)
	if err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}
	manifestScannedCounter.WithLabelValues("selectScanned").Add(1)
	manifestScannedDuration.WithLabelValues("selectScanned").Observe(time.Since(start).Seconds())
	defer rows.Close()
	var t int64
	for rows.Next() {
		if err := rows.Scan(&t); err != nil {
			return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
		}
		foundIDs[t] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}

	// compare the expectedIDs array with our foundIDs. if we get a lookup
	// miss we can say the manifest has not been scanned by all the layers provided
	for _, id := range expectedIDs {
		if _, ok := foundIDs[id]; !ok {
			return false, nil
		}
	}

	return true, nil
}
