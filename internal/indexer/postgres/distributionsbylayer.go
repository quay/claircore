package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	distributionByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "distributionbylayer_total",
			Help:      "The count of all queries issued in the DistributionsByLayer method",
		},
		[]string{"query"},
	)

	distributionByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "distributionbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the DistributionByLayer method",
		},
		[]string{"query"},
	)
)

//go:embed sql/distributions_by_layer.sql
var distributionsByLayerSQL string

func (s *store) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err := s.pool.QueryRow(ctx, selectScannerSQL, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		done()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve distribution ids for scanner %q: %w", scnr, err)
		}
		distributionByLayerCounter.WithLabelValues("selectScanner").Add(1)
		distributionByLayerDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())
	}

	ctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, distributionsByLayerSQL, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:distributionsByLayer no distribution found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:distributionsByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	protoRecordCounter.WithLabelValues("query").Add(1)
	protoRecordDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Distribution{}
	for rows.Next() {
		var dist claircore.Distribution

		var id int64
		err := rows.Scan(
			&id,
			&dist.Name,
			&dist.DID,
			&dist.Version,
			&dist.VersionCodeName,
			&dist.VersionID,
			&dist.Arch,
			&dist.CPE,
			&dist.PrettyName,
		)
		dist.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution: %w", err)
		}

		res = append(res, &dist)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
