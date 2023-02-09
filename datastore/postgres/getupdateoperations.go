package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	getLatestUpdateRefCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getlatestupdateref_total",
			Help:      "Total number of database queries issued in the GetLatestUpdateRef method.",
		},
		[]string{"query"},
	)
	getLatestUpdateRefDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getlatestupdateref_duration_seconds",
			Help:      "The duration of all queries issued in the GetLatestUpdateRef method",
		},
		[]string{"query"},
	)
	getLatestRefsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getlatestrefs_total",
			Help:      "Total number of database queries issued in the getLatestRefs method.",
		},
		[]string{"query"},
	)
	getLatestRefsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getlatestrefs_duration_seconds",
			Help:      "The duration of all queries issued in the getLatestRefs method",
		},
		[]string{"query"},
	)
	getUpdateOperationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdateoperations_total",
			Help:      "Total number of database queries issued in the getUpdateOperations method.",
		},
		[]string{"query"},
	)
	getUpdateOperationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdateoperations_duration_seconds",
			Help:      "The duration of all queries issued in the getUpdateOperations method",
		},
		[]string{"query"},
	)
)

// GetLatestUpdateRef implements driver.Updater.
func (s *MatcherStore) GetLatestUpdateRef(ctx context.Context, kind driver.UpdateKind) (uuid.UUID, error) {
	const (
		op                 = `datastore/postgres/MatcherStore.GetLatestUpdateRef`
		query              = `SELECT ref FROM update_operation ORDER BY id USING > LIMIT 1;`
		queryEnrichment    = `SELECT ref FROM update_operation WHERE kind = 'enrichment' ORDER BY id USING > LIMIT 1;`
		queryVulnerability = `SELECT ref FROM update_operation WHERE kind = 'vulnerability' ORDER BY id USING > LIMIT 1;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	var q string
	var label string
	switch kind {
	case "":
		q = query
		label = "query"
	case driver.EnrichmentKind:
		q = queryEnrichment
		label = "query_enrichment"
	case driver.VulnerabilityKind:
		q = queryVulnerability
		label = "query_vulnerability"
	}

	defer prometheus.NewTimer(getLatestUpdateRefDuration.WithLabelValues(label)).ObserveDuration()
	defer getLatestUpdateRefCounter.WithLabelValues(label).Inc()
	var ref uuid.UUID
	if err := s.pool.QueryRow(ctx, q).Scan(&ref); err != nil {
		return uuid.Nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrInternal,
			Message: "error querying latest UpdateOperation",
			Inner:   err,
		}
	}
	return ref, nil
}

func (s *MatcherStore) GetLatestUpdateRefs(ctx context.Context, kind driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	const (
		op                 = `datastore/postgres/MatcherStore.GetLatestUpdateRefs`
		query              = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation ORDER BY updater, id USING >;`
		queryEnrichment    = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation WHERE kind = 'enrichment' ORDER BY updater, id USING >;`
		queryVulnerability = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation WHERE kind = 'vulnerability' ORDER BY updater, id USING >;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	var q string
	var label string
	switch kind {
	case "":
		q = query
		label = "query"
	case driver.EnrichmentKind:
		q = queryEnrichment
		label = "query_enrichment"
	case driver.VulnerabilityKind:
		q = queryVulnerability
		label = "query_vulnerability"
	}

	ret := make(map[string][]driver.UpdateOperation)
	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		defer prometheus.NewTimer(getLatestRefsDuration.WithLabelValues(label)).ObserveDuration()
		defer getLatestRefsCounter.WithLabelValues(label).Inc()
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "query error",
				Inner:   err,
			}
		}
		defer rows.Close()

		for rows.Next() {
			ops := []driver.UpdateOperation{}
			ops = append(ops, driver.UpdateOperation{})
			uo := &ops[len(ops)-1]
			err := rows.Scan(
				&uo.Updater,
				&uo.Ref,
				&uo.Fingerprint,
				&uo.Date,
			)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: fmt.Sprintf("failed to scan update operation for updater %q", uo.Updater),
					Inner:   err,
				}
			}
			ret[uo.Updater] = ops
		}
		if err := rows.Err(); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error deserializing response",
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
		return nil, domErr
	}
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("found updaters")
	return ret, nil
}

func (s *MatcherStore) GetUpdateOperations(ctx context.Context, kind driver.UpdateKind, updater ...string) (map[string][]driver.UpdateOperation, error) {
	const (
		op                 = `datastore/postgres/MatcherStore.GetUpdateOperations`
		query              = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) ORDER BY id DESC;`
		queryVulnerability = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) AND kind = 'vulnerability' ORDER BY id DESC;`
		queryEnrichment    = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) AND kind = 'enrichment' ORDER BY id DESC;`
		getUpdaters        = `SELECT DISTINCT(updater) FROM update_operation;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", op)

	var q string
	var label string
	switch kind {
	case "":
		q = query
		label = "query"
	case driver.EnrichmentKind:
		q = queryEnrichment
		label = "query_enrichment"
	case driver.VulnerabilityKind:
		q = queryVulnerability
		label = "query_vulnerability"
	}

	// The response (nil, nil) is a valid and expected, so this is initialized
	// before use inside the closure.
	var out map[string][]driver.UpdateOperation
	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		// Get distinct updaters from database if nothing specified.
		if len(updater) == 0 {
			if err := func() error {
				defer prometheus.NewTimer(getUpdateOperationsDuration.WithLabelValues("getUpdaters")).ObserveDuration()
				defer getUpdateOperationsCounter.WithLabelValues("getUpdaters").Inc()
				rows, err := tx.Query(ctx, getUpdaters)
				switch {
				case err == nil:
				case errors.Is(err, pgx.ErrNoRows):
					return nil
				default:
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: "failed to get distinct updates",
						Inner:   err,
					}
				}
				defer rows.Close()
				for rows.Next() {
					var u string
					err := rows.Scan(&u)
					if err != nil {
						return &claircore.Error{
							Op:      op,
							Kind:    claircore.ErrInternal,
							Message: "failed to deserialize updater",
							Inner:   err,
						}
					}
					updater = append(updater, u)
				}
				if err := rows.Err(); err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: "error deserializing response",
						Inner:   err,
					}
				}
				return nil
			}(); err != nil {
				return err
			}
		}

		defer getUpdateOperationsCounter.WithLabelValues(label).Inc()
		defer prometheus.NewTimer(getUpdateOperationsDuration.WithLabelValues(label)).ObserveDuration()
		rows, err := tx.Query(ctx, q, updater)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to get distinct updates",
				Inner:   err,
			}
		}
		defer rows.Close()
		out = make(map[string][]driver.UpdateOperation)

		for rows.Next() {
			var uo driver.UpdateOperation
			err := rows.Scan(
				&uo.Ref,
				&uo.Updater,
				&uo.Fingerprint,
				&uo.Date,
			)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "failed to deserialize update operation",
					Inner:   err,
				}
			}
			out[uo.Updater] = append(out[uo.Updater], uo)
		}
		if err := rows.Err(); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error deserializing response",
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
		return nil, domErr
	}
	return out, nil
}
