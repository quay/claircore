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
	packagesByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "packagesbylayer_total",
			Help:      "Total number of database queries issued in the PackagesByLayer method.",
		},
		[]string{"query"},
	)

	packagesByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "packagesbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the PackagesByLayer method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Package, error) {
	const (
		query = `
SELECT
	package.id,
	package.name,
	package.kind,
	package.version,
	package.norm_kind,
	package.norm_version,
	package.module,
	package.arch,
	source_package.id,
	source_package.name,
	source_package.kind,
	source_package.version,
	source_package.module,
	source_package.arch,
	package_scanartifact.package_db,
	package_scanartifact.repository_hint,
	package_scanartifact.filepath
FROM
	package_scanartifact
	LEFT JOIN package ON
			package_scanartifact.package_id = package.id
	LEFT JOIN package AS source_package ON
			package_scanartifact.source_id
			= source_package.id
	JOIN layer ON layer.hash = $1
WHERE
	package_scanartifact.layer_id = layer.id
	AND package_scanartifact.scanner_id = ANY ($2);
`
	)

	if len(scnrs) == 0 {
		return []*claircore.Package{}, nil
	}
	// get scanner ids
	scannerIDs, err := s.selectScanners(scnrs)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:packagesByLayer no packages found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:packagesByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	packagesByLayerCounter.WithLabelValues("query").Add(1)
	packagesByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Package{}
	for rows.Next() {
		var pkg claircore.Package
		var spkg claircore.Package

		var id, srcID int64
		var nKind, fPath *string
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,
			&nKind,
			&pkg.NormalizedVersion,
			&pkg.Module,
			&pkg.Arch,

			&srcID,
			&spkg.Name,
			&spkg.Kind,
			&spkg.Version,
			&spkg.Module,
			&spkg.Arch,

			&pkg.PackageDB,
			&pkg.RepositoryHint,
			&fPath,
		)
		pkg.ID = strconv.FormatInt(id, 10)
		spkg.ID = strconv.FormatInt(srcID, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan packages: %w", err)
		}
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
		}
		if fPath != nil {
			pkg.Filepath = *fPath
		}
		// nest source package
		pkg.Source = &spkg

		res = append(res, &pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
