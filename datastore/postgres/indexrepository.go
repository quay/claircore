package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
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

	// NOTE(hank) The repository insert batching could use lots of memory. A
	// previous version of this code was using a cutoff size of 500 entries, so
	// it's unlikely that it was ever hit and removing it shouldn't noticeably
	// change behavior.
	var repoBatch, assocBatch pgx.Batch
	for _, repo := range repos {
		repoBatch.Queue(insert,
			repo.Name,
			repo.Key,
			repo.URI,
			repo.CPE,
		)
	}
	for _, repo := range repos {
		assocBatch.Queue(insertWith,
			repo.Name,
			repo.Key,
			repo.URI,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			l.Hash,
		)
	}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var start time.Time
		var err error

		start = time.Now()
		err = tx.SendBatch(ctx, &repoBatch).Close()
		indexRepositoriesCounter.WithLabelValues("insert_batch").Add(1)
		indexRepositoriesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())
		if err != nil {
			return fmt.Errorf("batch insert failed for repos: %w", err)
		}

		start = time.Now()
		err = tx.SendBatch(ctx, &assocBatch).Close()
		indexRepositoriesCounter.WithLabelValues("insertWith_batch").Add(1)
		indexRepositoriesDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())
		if err != nil {
			return fmt.Errorf("batch insert failed for repo association: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("IndexRepositories failed: %w", err)
	}
	return nil
}
