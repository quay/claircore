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
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

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
func (s *Store) GetLatestUpdateRef(ctx context.Context) (uuid.UUID, error) {
	const query = `SELECT ref FROM update_operation ORDER BY id USING > LIMIT 1;`
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/getLatestRef"))

	var ref uuid.UUID
	start := time.Now()
	if err := s.pool.QueryRow(ctx, query).Scan(&ref); err != nil {
		return uuid.Nil, err
	}
	getLatestUpdateRefCounter.WithLabelValues("query").Add(1)
	getLatestUpdateRefDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	return ref, nil
}

func getLatestRefs(ctx context.Context, pool *pgxpool.Pool) (map[string][]driver.UpdateOperation, error) {
	const query = `SELECT DISTINCT ON (updater) updater, ref, fingerprint, date FROM update_operation ORDER BY updater, id USING >;`
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/getLatestRefs"))

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

func getUpdateOperations(ctx context.Context, pool *pgxpool.Pool, updater ...string) (map[string][]driver.UpdateOperation, error) {
	const (
		query       = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater = $1 ORDER BY id DESC;`
		getUpdaters = `SELECT DISTINCT(updater) FROM update_operation;`
	)
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/getUpdateOperations"))

	tx, err := pool.Begin(ctx)
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
			return nil, nil
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

	// Take care to close the rows object on every iteration.
	var rows pgx.Rows
	for _, u := range updater {

		start := time.Now()

		rows, err = tx.Query(ctx, query, u)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			zlog.Warn(ctx).Str("updater", u).Msg("no update operations for this updater")
			rows.Close()
			continue
		default:
			rows.Close()
			return nil, fmt.Errorf("failed to retrieve update operation for updater %v: %w", updater, err)
		}
		ops := []driver.UpdateOperation{}

		getUpdateOperationsCounter.WithLabelValues("query").Add(1)
		getUpdateOperationsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

		for rows.Next() {
			ops = append(ops, driver.UpdateOperation{})
			uo := &ops[len(ops)-1]
			err := rows.Scan(
				&uo.Ref,
				&uo.Updater,
				&uo.Fingerprint,
				&uo.Date,
			)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", u, err)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out[u] = ops
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return out, nil
}
