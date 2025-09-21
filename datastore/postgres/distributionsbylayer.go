package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
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

func (s *IndexerStore) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	const (
		query = `
		SELECT dist.id,
			   dist.name,
			   dist.did,
			   dist.version,
			   dist.version_code_name,
			   dist.version_id,
			   dist.arch,
			   dist.cpe,
			   dist.pretty_name
		FROM dist_scanartifact
				 LEFT JOIN dist ON dist_scanartifact.dist_id = dist.id
				 JOIN layer ON layer.hash = $1
		WHERE dist_scanartifact.layer_id = layer.id
		  AND dist_scanartifact.scanner_id = ANY($2);
		`
	)

	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}

	scannerIDs, err := s.selectScanners(scnrs)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:distributionsByLayer no distribution found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:distributionsByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	distributionByLayerCounter.WithLabelValues("query").Add(1)
	distributionByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
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
