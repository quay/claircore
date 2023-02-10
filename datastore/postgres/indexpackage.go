package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
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
		op     = `datastore/postgres/IndexerStore.IndexPackages`
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
		INTO package_scanartifact (layer_id, package_db, repository_hint, package_id, source_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				$15,
				$16,
				(SELECT package_id FROM binary_package),
				(SELECT source_id FROM source_package),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := func() error {
			defer prometheus.NewTimer(indexPackageDuration.WithLabelValues("insert_batch")).ObserveDuration()
			defer indexPackageCounter.WithLabelValues("insert_batch").Inc()
			skipCt := 0
			stmt, err := tx.Prepare(ctx, "insertPackageStmt", insert)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, pkg := range pkgs {
				if pkg.Name == "" {
					skipCt++
				}
				if pkg.Source == nil {
					pkg.Source = &zeroPackage
				}

				if err := queueInsert(ctx, batch, stmt.Name, pkg.Source); err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("failed to queue insert for package %q", pkg.Source.Name),
						Inner:   err,
					}
				}
				if err := queueInsert(ctx, batch, stmt.Name, pkg); err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("failed to queue insert for package %q", pkg.Name),
						Inner:   err,
					}
				}
			}
			if err := batch.Done(ctx); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "final batch insert failed for package",
					Inner:   err,
				}
			}
			zlog.Debug(ctx).
				Int("skipped", skipCt).
				Int("inserted", len(pkgs)-skipCt).
				Msg("packages inserted")
			return nil
		}(); err != nil {
			return err
		}

		if err := func() error {
			defer prometheus.NewTimer(indexPackageDuration.WithLabelValues("insertWith_batch")).ObserveDuration()
			defer indexPackageCounter.WithLabelValues("insertWith_batch").Inc()
			skipCt := 0
			stmt, err := tx.Prepare(ctx, "insertPackageScanArtifactWith", insertWith)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			// make package scan artifacts
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, pkg := range pkgs {
				if pkg.Name == "" {
					skipCt++
					continue
				}
				err := batch.Queue(
					ctx,
					stmt.SQL,
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
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("failed to queue insert for package_scanartifact %q", pkg.Name),
						Inner:   err,
					}
				}
			}
			if err := batch.Done(ctx); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "final batch insert failed for package_scanartifact",
					Inner:   err,
				}
			}
			zlog.Debug(ctx).
				Int("skipped", skipCt).
				Int("inserted", len(pkgs)-skipCt).
				Msg("scanartifacts inserted")
			return nil
		}(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		var domErr *claircore.Error
		if !errors.As(err, &domErr) {
			domErr = &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "unexpected database error",
				Inner:   err,
			}
		}
		return domErr
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
	return b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, vKind, vNorm, pkg.Module, pkg.Arch,
	)
}
