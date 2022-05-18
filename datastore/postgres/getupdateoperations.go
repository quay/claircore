package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

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
		query              = `SELECT ref FROM update_operation ORDER BY id USING > LIMIT 1;`
		queryEnrichment    = `SELECT ref FROM update_operation WHERE kind = 'enrichment' ORDER BY id USING > LIMIT 1;`
		queryVulnerability = `SELECT ref FROM update_operation WHERE kind = 'vulnerability' ORDER BY id USING > LIMIT 1;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/getLatestRef")

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

	var ref uuid.UUID
	start := time.Now()
	if err := s.pool.QueryRow(ctx, q).Scan(&ref); err != nil {
		return uuid.Nil, err
	}
	getLatestUpdateRefCounter.WithLabelValues(label).Add(1)
	getLatestUpdateRefDuration.WithLabelValues(label).Observe(time.Since(start).Seconds())
	return ref, nil
}

func (s *MatcherStore) GetLatestUpdateRefs(ctx context.Context, kind driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	const (
		query              = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation ORDER BY updater, id USING >;`
		queryEnrichment    = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation WHERE kind = 'enrichment' ORDER BY updater, id USING >;`
		queryVulnerability = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation WHERE kind = 'vulnerability' ORDER BY updater, id USING >;`
	)

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

	start := time.Now()

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}

	getLatestRefsCounter.WithLabelValues(label).Add(1)
	getLatestRefsDuration.WithLabelValues(label).Observe(time.Since(start).Seconds())

	defer rows.Close()

	ret := make(map[string][]driver.UpdateOperation)
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
			rows.Close()
			return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", uo.Updater, err)
		}
		ret[uo.Updater] = ops
	}
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("found updaters")
	return ret, nil
}

func getLatestRefs(ctx context.Context, pool *pgxpool.Pool) (map[string][]driver.UpdateOperation, error) {
	const query = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation ORDER BY updater, id USING >;`
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/getLatestRefs")

	start := time.Now()

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	getLatestRefsCounter.WithLabelValues("query").Add(1)
	getLatestRefsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	defer rows.Close()

	ret := make(map[string][]driver.UpdateOperation)
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
			rows.Close()
			return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", uo.Updater, err)
		}
		ret[uo.Updater] = ops
	}
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("found updaters")
	return ret, nil
}

func (s *MatcherStore) GetUpdateOperations(ctx context.Context, kind driver.UpdateKind, updater ...string) (map[string][]driver.UpdateOperation, error) {
	const (
		query              = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) ORDER BY id DESC;`
		queryVulnerability = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) AND kind = 'vulnerability' ORDER BY id DESC;`
		queryEnrichment    = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = ANY($1) AND kind = 'enrichment' ORDER BY id DESC;`
		getUpdaters        = `SELECT DISTINCT(updater) FROM update_operation;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/getUpdateOperations")

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	out := make(map[string][]driver.UpdateOperation)

	// Get distinct updaters from database if nothing specified.
	if len(updater) == 0 {
		updater = []string{}

		start := time.Now()

		rows, err := tx.Query(ctx, getUpdaters)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return out, nil
		default:
			return nil, fmt.Errorf("failed to get distinct updates: %w", err)
		}

		getUpdateOperationsCounter.WithLabelValues("getUpdaters").Add(1)
		getUpdateOperationsDuration.WithLabelValues("getUpdaters").Observe(time.Since(start).Seconds())

		defer rows.Close() // OK to defer and call, as per docs.

		for rows.Next() {
			var u string
			err := rows.Scan(&u)
			if err != nil {
				return nil, fmt.Errorf("failed to scan updater: %w", err)
			}
			updater = append(updater, u)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows.Close()
	}

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

	start := time.Now()
	rows, err := tx.Query(ctx, q, updater)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to get distinct updates: %w", err)
	}
	getUpdateOperationsCounter.WithLabelValues(label).Add(1)
	getUpdateOperationsDuration.WithLabelValues(label).Observe(time.Since(start).Seconds())

	for rows.Next() {
		var uo driver.UpdateOperation
		err := rows.Scan(
			&uo.Ref,
			&uo.Updater,
			&uo.Fingerprint,
			&uo.Date,
		)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", uo.Updater, err)
		}
		out[uo.Updater] = append(out[uo.Updater], uo)
	}
	return out, nil
}
