package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

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
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
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
		op = `datastore/postgres/IndexerStore.DistributionsByLayer`
	)

	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}
	ctx = zlog.ContextWithValues(ctx, "component", op)

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		done()
		if err != nil {
			return nil, &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: fmt.Sprintf("failed to retrieve distribution ids for scanner %q", scnr),
				Inner:   err,
			}
		}
		distributionByLayerCounter.WithLabelValues("selectScanner").Add(1)
		distributionByLayerDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())
	}

	ctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrPrecondition,
			Message: fmt.Sprintf("no distribution found for layer (%v) and scanners (%v)", hash, scnrs),
			Inner:   err,
		}
	default:
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrInternal,
			Message: fmt.Sprintf("error for layer (%v) and scanners (%v)", hash, scnrs),
			Inner:   err,
		}
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
			return nil, &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to deserialize distribution",
				Inner:   err,
			}
		}

		res = append(res, &dist)
	}
	if err := rows.Err(); err != nil {
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrInternal,
			Message: "error deserializing distributions",
			Inner:   err,
		}
	}

	return res, nil
}
