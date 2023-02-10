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
	indexRepositoriesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexrepositories_total",
			Help:      "Total number of database queries issued in the IndexRepositories method.",
		},
		[]string{"query"},
	)

	indexRepositoriesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexrepositories_duration_seconds",
			Help:      "The duration of all queries issued in the IndexRepositories method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		op     = `datastore/postgres/IndexerStore.IndexRepositories`
		insert = `
		INSERT INTO repo
			(name, key, uri, cpe)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name, key, uri) DO NOTHING;
		`

		insertWith = `
		WITH repositories AS (
			SELECT id AS repo_id
			FROM repo
			WHERE name = $1
			  AND key = $2
			  AND uri = $3
		),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $4
				   AND version = $5
				   AND kind = $6
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $7
			 )
		INSERT
		INTO repo_scanartifact (layer_id, repo_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT repo_id FROM repositories),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := func() error {
			defer prometheus.NewTimer(indexRepositoriesDuration.WithLabelValues("insert_batch")).ObserveDuration()
			defer indexRepositoriesCounter.WithLabelValues("insert_batch").Inc()
			stmt, err := tx.Prepare(ctx, "insertRepoStmt", insert)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, repo := range repos {
				err := batch.Queue(ctx, stmt.SQL,
					repo.Name,
					repo.Key,
					repo.URI,
					repo.CPE,
				)
				if err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("failed to queue insert for repo %q", repo.Name),
						Inner:   err,
					}
				}
			}
			if err := batch.Done(ctx); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "final batch insert failed for repo",
					Inner:   err,
				}
			}
			return nil
		}(); err != nil {
			return err
		}

		if err := func() error {
			defer prometheus.NewTimer(indexRepositoriesDuration.WithLabelValues("insertWith_batch")).ObserveDuration()
			defer indexRepositoriesCounter.WithLabelValues("insertWith_batch").Inc()
			stmt, err := tx.Prepare(ctx, "insertRepoScanArtifactWith", insertWith)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to create statement",
					Inner:   err,
				}
			}
			batch := microbatch.NewInsert(tx, 500, time.Minute)
			for _, repo := range repos {
				err := batch.Queue(ctx, stmt.SQL,
					repo.Name,
					repo.Key,
					repo.URI,
					scnr.Name(),
					scnr.Version(),
					scnr.Kind(),
					l.Hash,
				)
				if err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: fmt.Sprintf("failed to queue insert for repo_scanartifact %q", repo.Name),
						Inner:   err,
					}
				}
			}
			if err := batch.Done(ctx); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "final batch insert failed for repo_scanartifact",
					Inner:   err,
				}
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
