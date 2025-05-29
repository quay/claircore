package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/microbatch"
)

var zeroPackage = claircore.Package{}

var (
	indexPackageCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_total",
			Help:      "Total number of database queries issued in the IndexPackage method.",
		},
		[]string{"query"},
	)

	indexPackageDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_duration_seconds",
			Help:      "The duration of all queries issued in the IndexPackage method",
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

	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexPackages")
	// obtain a transaction scoped batch
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertPackageStmt, err := tx.Prepare(ctx, "insertPackageStmt", insert)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	insertPackageScanArtifactWithStmt, err := tx.Prepare(ctx, "insertPackageScanArtifactWith", insertWith)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	skipCt := 0

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
		}
		if pkg.Source == nil {
			pkg.Source = &zeroPackage
		}

		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg.Source); err != nil {
			return err
		}
		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg); err != nil {
			return err
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for pkg: %w", err)
	}
	indexPackageCounter.WithLabelValues("insert_batch").Add(1)
	indexPackageDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("packages inserted")

	skipCt = 0
	// make package scan artifacts
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)

	start = time.Now()
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
			continue
		}
		err := mBatcher.Queue(
			ctx,
			insertPackageScanArtifactWithStmt.SQL,
			pkg.Source.Name,
			pkg.Source.Kind,
			pkg.Source.Version,
			pkg.Source.Module,
			pkg.Source.Arch,
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
		if err != nil {
			return fmt.Errorf("batch insert failed for package_scanartifact %v: %w", pkg, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for package_scanartifact: %w", err)
	}
	indexPackageCounter.WithLabelValues("insertWith_batch").Add(1)
	indexPackageDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())
	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("scanartifacts inserted")

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %w", err)
	}
	return nil
}

func queueInsert(ctx context.Context, b *microbatch.Insert, stmt string, pkg *claircore.Package) error {
	// There is a disconnect between the claircore.Package.NormalizedVersion field
	// (which is never nil) and the DB column norm_version (which can be null) so
	// we need to key off the kind to judge whether to leave it null or not.
	// TODO(crozzy): Explore if we can include this logic as part of the Version's EncodePlan.
	normVer := &pkg.NormalizedVersion
	if pkg.NormalizedVersion.Kind == "" {
		normVer = nil
	}
	err := b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, pkg.NormalizedVersion.Kind, normVer, pkg.Module, pkg.Arch,
	)
	if err != nil {
		return fmt.Errorf("failed to queue insert for package %q: %w", pkg.Name, err)
	}
	return nil
}
