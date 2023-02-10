package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v4"
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
			Help:      "The duration of all queries issued in the IndexManifest method.",
		},
		[]string{"query"},
	)
)

func (s *IndexerStore) IndexManifest(ctx context.Context, ir *claircore.IndexReport) error {
	const (
		op    = `datastore/postgres/IndexerStore.IndexManifest`
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
	ctx = zlog.ContextWithValues(ctx, "component", op)

	hash := ir.Hash.String()
	if hash == "" {
		return &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrPrecondition,
			Message: "empty digest",
		}
	}

	records := ir.IndexRecords()
	if len(records) == 0 {
		zlog.Warn(ctx).Msg("manifest being indexed has 0 index records")
		return nil
	}

	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		defer prometheus.NewTimer(indexManifestDuration.WithLabelValues("query_batch")).ObserveDuration()
		defer indexManifestCounter.WithLabelValues("query_batch").Inc()
		stmt, err := tx.Prepare(ctx, "queryStmt", query)
		if err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to create statement",
				Inner:   err,
			}
		}

		batch := microbatch.NewInsert(tx, 500, time.Minute)
		for _, record := range records {
			// ignore nil packages
			if record.Package == nil {
				continue
			}

			v, err := toValues(*record)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrPrecondition,
					Message: "record has an invalid id",
					Inner:   err,
				}
			}

			// if source package exists create record
			if v[0] != nil {
				if err := batch.Queue(ctx, stmt.SQL,
					v[0], v[2], v[3], hash,
				); err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrPrecondition,
						Message: "batch insert failed for source record",
						Inner:   err,
					}
				}
			}
			if err := batch.Queue(ctx, stmt.SQL,
				v[1], v[2], v[3], hash,
			); err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrPrecondition,
					Message: "batch insert failed for record",
					Inner:   err,
				}
			}
		}
		if err := batch.Done(ctx); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "final batch insert failed for record",
				Inner:   err,
			}
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

// ToValues is a helper method which checks for nil pointers inside an
// IndexRecord before returning an associated pointer to the artifact in
// question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) (res [4]*uint64, err error) {
	var backing [4]uint64
	if r.Package != nil {
		if r.Package.Source != nil {
			backing[0], err = strconv.ParseUint(r.Package.Source.ID, 10, 64)
			if err != nil {
				return res, fmt.Errorf("source package id %v: %w", r.Package.ID, err)
			}
			res[0] = &backing[0]
		}
		backing[1], err = strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %w", r.Package.ID, err)
		}
		res[1] = &backing[1]
	}
	if r.Distribution != nil {
		backing[2], err = strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %w", r.Distribution.ID, err)
		}
		res[2] = &backing[2]
	}
	if r.Repository != nil {
		backing[3], err = strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("repository id %v: %w", r.Package.ID, err)
		}
		res[3] = &backing[3]
	}

	return res, nil
}
