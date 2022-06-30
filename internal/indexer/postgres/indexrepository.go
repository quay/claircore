package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
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

var (
	//go:embed sql/insert_repository.sql
	insertRepositorySQL string
	//go:embed sql/associate_layer_repository_scanner.sql
	associateLayerPkgSQL string
)

func (s *store) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoStmt, err := tx.Prepare(tctx, "insertRepoStmt", insertRepositorySQL)
	done()
	if err != nil {
		return fmt.Errorf("failed to create insert repo statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoScanArtifactWithStmt, err := tx.Prepare(tctx, "insertRepoScanArtifactWith", associateLayerPkgSQL)
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
