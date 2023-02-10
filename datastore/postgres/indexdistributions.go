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

var (
	indexDistributionsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_total",
			Help:      "Total number of database queries issued in the IndexDistributions method.",
		},
		[]string{"query"},
	)

	indexDistributionsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_duration_seconds",
			Help:      "The duration of all queries issued in the IndexDistributions method.",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		op     = `datastore/postgres/IndexerStore.IndexDistributions`
		insert = `
		INSERT INTO dist 
			(name, did, version, version_code_name, version_id, arch, cpe, pretty_name) 
		VALUES 
			($1, $2, $3, $4, $5, $6, $7, $8) 
		ON CONFLICT (name, did, version, version_code_name, version_id, arch, cpe, pretty_name) DO NOTHING;
		`
		insertWith = `
		WITH distributions AS (
			SELECT id AS dist_id
			FROM dist
			WHERE name = $1
			  AND did = $2
			  AND version = $3
			  AND version_code_name = $4
			  AND version_id = $5
			  AND arch = $6
			  AND cpe = $7
			  AND pretty_name = $8
		),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $9
				   AND version = $10
				   AND kind = $11
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $12
			 )
		INSERT
		INTO dist_scanartifact (layer_id, dist_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT dist_id FROM distributions),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite}, func(tx pgx.Tx) error {
		if err := func() error {
			defer prometheus.NewTimer(indexDistributionsDuration.WithLabelValues("insert_batch")).ObserveDuration()
			defer indexDistributionsCounter.WithLabelValues("insert_batch").Inc()
			stmt, err := tx.Prepare(ctx, "insertDistStmt", insert)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, dist := range dists {
				err := batch.Queue(
					ctx,
					stmt.SQL,
					dist.Name,
					dist.DID,
					dist.Version,
					dist.VersionCodeName,
					dist.VersionID,
					dist.Arch,
					dist.CPE,
					dist.PrettyName,
				)
				if err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("batch insert failed for dist %q", dist),
						Inner:   err,
					}
				}
			}
			if err := batch.Done(ctx); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "final batch insert failed for dist",
					Inner:   err,
				}
			}
			return nil
		}(); err != nil {
			return err
		}

		if err := func() error {
			defer prometheus.NewTimer(indexDistributionsDuration.WithLabelValues("insertWith_batch")).ObserveDuration()
			defer indexDistributionsCounter.WithLabelValues("insertWith_batch").Inc()
			stmt, err := tx.Prepare(ctx, "insertDistScanArtifactWith", insertWith)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, dist := range dists {
				err := batch.Queue(
					ctx,
					stmt.SQL,
					dist.Name,
					dist.DID,
					dist.Version,
					dist.VersionCodeName,
					dist.VersionID,
					dist.Arch,
					dist.CPE,
					dist.PrettyName,
					scnr.Name(),
					scnr.Version(),
					scnr.Kind(),
					layer.Hash,
				)
				if err != nil {
					return fmt.Errorf("batch insert failed for dist_scanartifact %v: %w", dist, err)
				}
			}
			if err := batch.Done(ctx); err != nil {
				return fmt.Errorf("final batch insert failed for dist_scanartifact: %w", err)
			}
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
