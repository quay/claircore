package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore/indexer"
)

var (
	registerScannerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_total",
			Help:      "Total number of database queries issued in the RegiterScanners method.",
		},
		[]string{"query"},
	)

	registerScannerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_duration_seconds",
			Help:      "The duration of all queries issued in the RegiterScanners method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	const (
		insert = `
INSERT
INTO
	scanner (name, version, kind)
VALUES
	($1, $2, $3)
ON CONFLICT
	(name, version, kind)
DO
	NOTHING;
`
		exists = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			scanner
		WHERE
			name = $1 AND version = $2 AND kind = $3
	);
`
	)

	var ok bool
	var err error
	for _, v := range vs {
		start := time.Now()
		err = s.pool.QueryRow(ctx, exists, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("exists").Add(1)
		registerScannerDuration.WithLabelValues("exists").Observe(time.Since(start).Seconds())
		if ok {
			continue
		}

		start = time.Now()
		_, err = s.pool.Exec(ctx, insert, v.Name(), v.Version(), v.Kind())
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("insert").Add(1)
		registerScannerDuration.WithLabelValues("insert").Observe(time.Since(start).Seconds())
	}

	return s.populateScanners(ctx)
}

const selectAllScanner = `
SELECT
	id, name, version, kind
FROM
	scanner;
`

func (s *IndexerStore) populateScanners(ctx context.Context) error {
	s.scanners = make(map[string]int64)
	rows, err := s.pool.Query(ctx, selectAllScanner)
	if err != nil {
		return fmt.Errorf("failed to retrieve scanners: %w", err)
	}
	for rows.Next() {
		var id int64
		var name, version, kind string
		err := rows.Scan(
			&id,
			&name,
			&version,
			&kind,
		)
		if err != nil {
			return fmt.Errorf("failed to scan scanners: %w", err)
		}
		s.scanners[makeScannerKey(name, version, kind)] = id
	}
	return nil
}

func (s *IndexerStore) selectScanners(vs indexer.VersionedScanners) ([]int64, error) {
	ids := make([]int64, len(vs))
	for i, v := range vs {
		id, ok := s.scanners[makeScannerKey(v.Name(), v.Version(), v.Kind())]
		if !ok {
			return nil, fmt.Errorf("failed to retrieve id for scanner %q", v.Name())
		}
		ids[i] = id
	}

	return ids, nil
}

func (s *IndexerStore) selectScanner(v indexer.VersionedScanner) (int64, error) {
	id, ok := s.scanners[makeScannerKey(v.Name(), v.Version(), v.Kind())]
	if !ok {
		return 0, fmt.Errorf("failed to retrieve id for scanner %q", v.Name())
	}
	return id, nil
}

func makeScannerKey(name, version, kind string) string {
	return name + "_" + version + "_" + kind
}
