package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
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

var (
	//go:embed sql/insert_package.sql
	insertPackageSQL string
	//go:embed sql/associate_layer_package_scanner.sql
	associateLayerPackageSQL string
)

// IndexPackages indexes all provided packages along with creating a scan artifact.
//
// If a source package is nested inside a binary package we index the source
// package first and then create a relation between the binary package and
// source package.
//
// Scan artifacts are used to determine if a particular layer has been scanned by a
// particular scanner. See the LayerScanned method for more details.
func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/indexer/postgres/indexPackages")
	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertPackageStmt, err := tx.Prepare(tctx, "insertPackageStmt", insertPackageSQL)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertPackageScanArtifactWithStmt, err := tx.Prepare(tctx, "insertPackageScanArtifactWith", associateLayerPackageSQL)
	done()
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

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %w", err)
	}
	return nil
}

func queueInsert(ctx context.Context, b *microbatch.Insert, stmt string, pkg *claircore.Package) error {
	var vKind *string
	var vNorm []int32
	if pkg.NormalizedVersion.Kind != "" {
		vKind = &pkg.NormalizedVersion.Kind
		vNorm = pkg.NormalizedVersion.V[:]
	}
	err := b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, vKind, vNorm, pkg.Module, pkg.Arch,
	)
	if err != nil {
		return fmt.Errorf("failed to queue insert for package %q: %w", pkg.Name, err)
	}
	return nil
}
