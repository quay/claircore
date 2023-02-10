package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

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
		op            = `datastore/postgres/IndexerStore.LayerScanned`
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
	ctx = zlog.ContextWithValues(ctx, "component", op)

	var err error
	var scannerID int64
	err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		defer prometheus.NewTimer(layerScannedDuration.WithLabelValues("selectScanner")).ObserveDuration()
		defer layerScannedCounter.WithLabelValues("selectScanner").Inc()
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerID)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrNoRows):
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrPrecondition,
				Message: fmt.Sprintf("scanner %q not found", scnr.Name()),
				Inner:   err,
			}
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error querying scanner",
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

	var ok bool
	err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		defer prometheus.NewTimer(layerScannedDuration.WithLabelValues("selectScanned")).ObserveDuration()
		defer layerScannedCounter.WithLabelValues("selectScanned").Inc()
		if err := c.QueryRow(ctx, selectScanned, hash.String(), scannerID).Scan(&ok); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error querying scanned status",
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
	return ok, nil
}
