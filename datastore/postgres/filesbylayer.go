package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	filesByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "filesbylayer_total",
			Help:      "The count of all queries issued in the FilesByLayer method",
		},
		[]string{"query"},
	)

	filesByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "filesbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the FilesByLayer method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) FilesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]claircore.File, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		SELECT file.path, file.kind
		FROM file_scanartifact
				 LEFT JOIN file ON file_scanartifact.file_id = file.id
				 JOIN layer ON layer.hash = $1
		WHERE file_scanartifact.layer_id = layer.id
		  AND file_scanartifact.scanner_id = ANY($2);
		`
	)

	if len(scnrs) == 0 {
		return []claircore.File{}, nil
	}

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		start := time.Now()
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		filesByLayerCounter.WithLabelValues("selectScanner").Add(1)
		filesByLayerDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve file ids for scanner %q: %w", scnr, err)
		}
	}

	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	filesByLayerCounter.WithLabelValues("query").Add(1)
	filesByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("no file found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("failed to retrieve file rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	defer rows.Close()

	res := []claircore.File{}
	var i int
	for rows.Next() {
		res = append(res, claircore.File{})

		err := rows.Scan(
			&res[i].Path,
			&res[i].Kind,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %w", err)
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
