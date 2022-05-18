package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/microbatch"
)

var (
	indexManifestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexmanifest_total",
			Help:      "Total number of database queries issued in the IndexManifest method.",
		},
		[]string{"query"},
	)

	indexManifestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexmanifest_duration_seconds",
			Help:      "The duration of all queries issued in the IndexManifest method",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexManifest(ctx context.Context, ir *claircore.IndexReport) error {
	const (
		query = `
		WITH manifests AS (
			SELECT id AS manifest_id
			FROM manifest
			WHERE hash = $4
		)
		INSERT
		INTO manifest_index(package_id, dist_id, repo_id, manifest_id)
		VALUES ($1, $2, $3, (SELECT manifest_id FROM manifests))
		ON CONFLICT DO NOTHING;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexManifest")

	if ir.Hash.String() == "" {
		return fmt.Errorf("received empty hash. cannot associate contents with a manifest hash")
	}
	hash := ir.Hash.String()

	records := ir.IndexRecords()
	if len(records) == 0 {
		zlog.Warn(ctx).Msg("manifest being indexed has 0 index records")
		return nil
	}

	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("postgres: indexManifest failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	queryStmt, err := tx.Prepare(tctx, "queryStmt", query)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, record := range records {
		// ignore nil packages
		if record.Package == nil {
			continue
		}

		v, err := toValues(*record)
		if err != nil {
			return fmt.Errorf("received a record with an invalid id: %v", err)
		}

		// if source package exists create record
		if v[0] != nil {
			err = mBatcher.Queue(
				ctx,
				queryStmt.SQL,
				v[0],
				v[2],
				v[3],
				hash,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for source package record %v: %w", record, err)
			}
		}

		err = mBatcher.Queue(
			ctx,
			queryStmt.SQL,
			v[1],
			v[2],
			v[3],
			hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package record %v: %w", record, err)
		}

	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed: %w", err)
	}
	indexManifestCounter.WithLabelValues("query_batch").Add(1)
	indexManifestDuration.WithLabelValues("query_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

// toValues is a helper method which checks for
// nil pointers inside an IndexRecord before
// returning an associated pointer to the artifact
// in question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) ([4]*uint64, error) {
	res := [4]*uint64{}

	if r.Package.Source != nil {
		id, err := strconv.ParseUint(r.Package.Source.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("source package id %v: %v", r.Package.ID, err)
		}
		res[0] = &id
	}

	if r.Package != nil {
		id, err := strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %v", r.Package.ID, err)
		}
		res[1] = &id

	}

	if r.Distribution != nil {
		id, err := strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %v", r.Distribution.ID, err)
		}
		res[2] = &id
	}

	if r.Repository != nil {
		id, err := strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			// return res, fmt.Errorf("repository id %v: %v", r.Package.ID, err)
			return res, nil
		}
		res[3] = &id
	}

	return res, nil
}
