package postgres

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var zeroPackage = claircore.Package{}

var (
	indexPackageCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_total",
			Help:      "Total number of database queries issued in the IndexPackages method.",
		},
		[]string{"query"},
	)

	indexPackageDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_duration_seconds",
			Help:      "The duration of all queries issued in the IndexPackages method",
		},
		[]string{"query"},
	)
)

// IndexPackages indexes all provided packages along with creating a scan artifact.
//
// If a source package is nested inside a binary package we index the source
// package first and then create a relation between the binary package and
// source package.
//
// Scan artifacts are used to determine if a particular layer has been scanned by a
// particular scanner. See the LayerScanned method for more details.
func (s *IndexerStore) IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		insert = ` 
		INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch)
		VALUES ($1, $2, $3, $4, $5::int[], $6, $7)
		ON CONFLICT (name, kind, version, module, arch) DO NOTHING;
		`

		insertWith = `
		WITH source_package AS (
			SELECT id AS source_id
			FROM package
			WHERE name = $1
			  AND kind = $2
			  AND version = $3
			  AND module = $4
			  AND arch = $5
		),
			 binary_package AS (
				 SELECT id AS package_id
				 FROM package
				 WHERE name = $6
				   AND kind = $7
				   AND version = $8
				   AND module = $9
				   AND arch = $10
			 ),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $11
				   AND version = $12
				   AND kind = $13
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $14
			 )
		INSERT
		INTO package_scanartifact (layer_id, package_db, repository_hint, filepath, package_id, source_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				$15,
				$16,
				$17,
				(SELECT package_id FROM binary_package),
				(SELECT source_id FROM source_package),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)

	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/IndexerStore.IndexPackages")

	var batch, assocBatch pgx.Batch
	skipCt := 0
	queueInsert := func(pkg *claircore.Package) {
		// There is a disconnect between the claircore.Package.NormalizedVersion field
		// (which is never nil) and the DB column norm_version (which can be null) so
		// we need to key off the kind to judge whether to leave it null or not.
		// TODO(crozzy): Explore if we can include this logic as part of the Version's EncodePlan.
		normVer := &pkg.NormalizedVersion
		if pkg.NormalizedVersion.Kind == "" {
			normVer = nil
		}
		batch.Queue(insert,
			pkg.Name, pkg.Kind, pkg.Version, pkg.NormalizedVersion.Kind, normVer, pkg.Module, pkg.Arch,
		)
	}
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
			// Original code has this not continue, but that seems wrong...
			continue
		}
		src := cmp.Or(pkg.Source, &zeroPackage)
		queueInsert(src)
		queueInsert(pkg)
		assocBatch.Queue(
			insertWith,
			src.Name,
			src.Kind,
			src.Version,
			src.Module,
			src.Arch,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			pkg.Module,
			pkg.Arch,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
			pkg.PackageDB,
			pkg.RepositoryHint,
			pkg.Filepath,
		)
	}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		start := time.Now()
		err := tx.SendBatch(ctx, &batch).Close()
		indexPackageCounter.WithLabelValues("insert_batch").Add(1)
		indexPackageDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())
		if err != nil {
			return err
		}
		zlog.Debug(ctx).
			Int("skipped", skipCt).
			Int("inserted", len(pkgs)-skipCt).
			Msg("packages inserted")

		start = time.Now()
		err = tx.SendBatch(ctx, &assocBatch).Close()
		indexPackageCounter.WithLabelValues("insertWith_batch").Add(1)
		indexPackageDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())
		zlog.Debug(ctx).
			Int("skipped", skipCt).
			Int("inserted", len(pkgs)-skipCt).
			Msg("scanartifacts inserted")
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("IndexPackages failed: %w", err)
	}
	return nil
}
