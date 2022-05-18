package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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
	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoStmt, err := tx.Prepare(tctx, "insertRepoStmt", insert)
	done()
	if err != nil {
		return fmt.Errorf("failed to create insert repo statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoScanArtifactWithStmt, err := tx.Prepare(tctx, "insertRepoScanArtifactWith", insertWith)
	done()
	if err != nil {
		return fmt.Errorf("failed to create insert repo scanartifact statement: %w", err)
	}

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			repo.CPE,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo: %w", err)
	}
	indexRepositoriesCounter.WithLabelValues("insert_batch").Add(1)
	indexRepositoriesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	// make repo scan artifacts

	start = time.Now()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoScanArtifactWithStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			l.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo_scanartifact %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo_scanartifact: %w", err)
	}
	indexRepositoriesCounter.WithLabelValues("insertWith_batch").Add(1)
	indexRepositoriesDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to commit tx: %w", err)
	}
	return nil
}
