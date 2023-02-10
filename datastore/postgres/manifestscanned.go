package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

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
		op            = `datastore/postgres/IndexerStore.ManifestScanned`
		selectScanned = `
		SELECT scanner_id
		FROM scanned_manifest
				 JOIN manifest ON scanned_manifest.manifest_id = manifest.id
		WHERE manifest.hash = $1;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	// get the ids of the scanners we are testing for.
	expectedIDs, err := s.selectScanners(ctx, vs)
	if err != nil {
		var domErr *claircore.Error
		if !errors.As(err, &domErr) {
			domErr = &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "unexpected database error",
				Inner:   err,
			}
		}
		return false, domErr
	}

	// get a map of the found ids which have scanned this package
	foundIDs := map[int64]struct{}{}
	err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		defer prometheus.NewTimer(manifestScannedDuration.WithLabelValues("selectScanned")).ObserveDuration()
		defer manifestScannedCounter.WithLabelValues("selectScanned").Inc()
		rows, err := c.Query(ctx, selectScanned, hash)
		if err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error querying scanned state",
				Inner:   err,
			}
		}
		defer rows.Close()
		var t int64
		for rows.Next() {
			if err := rows.Scan(&t); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "error deserializing scanner id",
					Inner:   err,
				}
			}
			foundIDs[t] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error deserializing scanner ids",
				Inner:   err,
			}
		}
		return nil
	})
	if err != nil {
		var domErr *claircore.Error
		if !errors.As(err, &domErr) {
			domErr = &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "unexpected database error",
				Inner:   err,
			}
		}
		return false, domErr
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
