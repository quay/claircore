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

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	repositoriesByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "repositoriesbylayer_total",
			Help:      "Total number of database queries issued in the RepositoriesByLayer method.",
		},
		[]string{"query"},
	)

	repositoriesByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "repositoriesbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the RepositoriesByLayer method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	const query = `
SELECT
	repo.id, repo.name, repo.key, repo.uri, repo.cpe
FROM
	repo_scanartifact
	LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
	JOIN layer ON layer.hash = $1
WHERE
	repo_scanartifact.layer_id = layer.id
	AND repo_scanartifact.scanner_id = ANY ($2);
`

	if len(scnrs) == 0 {
		return []*claircore.Repository{}, nil
	}
	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return nil, fmt.Errorf("unable to select scanners: %w", err)
	}

	ctx, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("no repositories found for layer, scanners set")
	default:
		return nil, fmt.Errorf("failed to retrieve repositories for layer, scanners set: %w", err)
	}
	repositoriesByLayerCounter.WithLabelValues("query").Add(1)
	repositoriesByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Repository{}
	for rows.Next() {
		var repo claircore.Repository

		var id int64
		err := rows.Scan(
			&id,
			&repo.Name,
			&repo.Key,
			&repo.URI,
			&repo.CPE,
		)
		repo.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan repositories: %w", err)
		}

		res = append(res, &repo)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
