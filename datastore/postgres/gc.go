package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore/libvuln/driver"
)

var (
	gcCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "gc_total",
			Help:      "Total number of database queries issued in the GC method.",
		},
		[]string{"query", "success"},
	)
	gcDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "gc_duration_seconds",
			Help:      "The duration of all queries issued in the GC method",
		},
		[]string{"query"},
	)
)

const (
	// GCThrottle sets a limit for the number of deleted update operations
	// (and subsequent cascade deletes in the uo_vuln table) that can occur in a GC run.
	GCThrottle = 50
)

// GC is split into two phases, first it will identify any update operations
// which are older then the provided keep value and delete these.
//
// Next it will perform updater based deletions of any vulns from the vuln table
// which are not longer referenced by update operations.
//
// The GC is throttled to not overload the database with cascade deletes.
// If a full GC is required run this method until the returned int64 value
// is 0.
func (s *MatcherStore) GC(ctx context.Context, keep int) (int64, error) {
	// obtain update operations which need deletin'
	ops, totalOps, err := eligibleUpdateOpts(ctx, s.pool, keep)
	if err != nil {
		return 0, err
	}

	// delete em', but not too many...
	if totalOps >= GCThrottle {
		ops = ops[:GCThrottle]
	}

	deletedOps, err := s.DeleteUpdateOperations(ctx, ops...)
	if err != nil {
		return totalOps - deletedOps, err
	}

	// get all updaters we know about.
	updaters, err := distinctUpdaters(ctx, s.pool)
	if err != nil {
		return totalOps - deletedOps, err
	}

	// issue concurrent updater-based deletion for known updaters
	// limit concurrency by available goroutines.
	cpus := int64(runtime.GOMAXPROCS(0))
	sem := semaphore.NewWeighted(cpus)

	errC := make(chan error, len(updaters[driver.VulnerabilityKind])+len(updaters[driver.EnrichmentKind]))

	for kind, us := range updaters {
		var cleanup cleanupFunc
		switch kind {
		case driver.VulnerabilityKind:
			cleanup = vulnCleanup
		case driver.EnrichmentKind:
			cleanup = enrichmentCleanup
		default:
			slog.ErrorContext(ctx, "unknown updater kind; skipping cleanup", "kind", string(kind))
			continue
		}
		for _, u := range us {
			err = sem.Acquire(ctx, 1)
			if err != nil {
				break
			}
			go func(cleanup cleanupFunc, u string) {
				defer sem.Release(1)
				err := cleanup(ctx, s.pool, u)
				if err != nil {
					errC <- err
				}
			}(cleanup, u)
		}
	}

	// unconditionally wait for all in-flight go routines to return.
	// the use of context.Background and lack of error checking is intentional.
	// all in-flight go routines are guarantee to release their sems.
	sem.Acquire(context.Background(), cpus)

	close(errC)
	if len(errC) > 0 {
		b := strings.Builder{}
		b.WriteString("encountered the following errors during gc: \n")
		for e := range errC {
			b.WriteString(e.Error() + "\n")
		}
		return totalOps - deletedOps, errors.New(b.String())
	}
	return totalOps - deletedOps, nil
}

// distinctUpdaters returns all updaters which have registered an update
// operation.
func distinctUpdaters(ctx context.Context, pool *pgxpool.Pool) (map[driver.UpdateKind][]string, error) {
	const (
		// will always contain at least two update operations
		selectUpdaters = `
SELECT DISTINCT(updater), kind FROM update_operation;
`
	)
	rows, err := pool.Query(ctx, selectUpdaters)
	if err != nil {
		return nil, fmt.Errorf("error selecting distinct updaters: %v", err)
	}
	defer rows.Close()

	updaters := make(map[driver.UpdateKind][]string)
	for rows.Next() {
		var (
			updater string
			kind    driver.UpdateKind
		)
		err := rows.Scan(&updater, &kind)
		switch err {
		case nil:
			// hop out
		default:
			return nil, fmt.Errorf("error scanning updater: %v", err)
		}
		updaters[kind] = append(updaters[kind], updater)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return updaters, nil
}

// eligibleUpdateOpts returns a list of update operation refs which exceed the specified
// keep value.
func eligibleUpdateOpts(ctx context.Context, pool *pgxpool.Pool, keep int) ([]uuid.UUID, int64, error) {
	const (
		// this query will return rows of UUID arrays.
		// each returned array are the UUIDs which exceed the provided keep value
		updateOps = `
WITH ordered_ops AS (
    SELECT array_agg(ref ORDER BY date DESC) AS refs FROM update_operation GROUP BY updater
)
SELECT ordered_ops.refs[$1:]
FROM ordered_ops
WHERE array_length(ordered_ops.refs, 1) > $2;
`
	)

	// gather any update operations exceeding our keep value.
	// keep+1 is used because PG's array slicing is inclusive,
	// we want to grab all items once after our keep value.
	m := []uuid.UUID{}

	start := time.Now()
	rows, err := pool.Query(ctx, updateOps, keep+1, keep)
	switch err {
	case nil:
	default:
		gcCounter.WithLabelValues("updateOps", "false").Inc()
		return nil, 0, fmt.Errorf("error querying for update operations: %v", err)
	}

	gcCounter.WithLabelValues("updateOps", "true").Inc()
	gcDuration.WithLabelValues("updateOps").Observe(time.Since(start).Seconds())

	defer rows.Close()
	for rows.Next() {
		var tmp []uuid.UUID
		err := rows.Scan(&tmp)
		if err != nil {
			return nil, 0, fmt.Errorf("error scanning update operations: %w", err)
		}
		m = append(m, tmp...)
	}
	if rows.Err() != nil {
		return nil, 0, rows.Err()
	}
	return m, int64(len(m)), nil
}

type cleanupFunc func(context.Context, *pgxpool.Pool, string) error

func vulnCleanup(ctx context.Context, pool *pgxpool.Pool, updater string) error {
	const (
		deleteOrphanedVulns = `
DELETE FROM vuln v1 USING
	vuln v2
	LEFT JOIN uo_vuln uvl
		ON v2.id = uvl.vuln
	WHERE uvl.vuln IS NULL
	AND v2.updater = $1
AND v1.id = v2.id;
`
	)

	start := time.Now()
	slog.DebugContext(ctx, "starting vuln clean up")
	res, err := pool.Exec(ctx, deleteOrphanedVulns, updater)
	if err != nil {
		gcCounter.WithLabelValues("deleteVulns", "false").Inc()
		return fmt.Errorf("failed while exec'ing vuln delete: %w", err)
	}
	slog.DebugContext(ctx, "vulns deleted", "rows affected", res.RowsAffected())
	gcCounter.WithLabelValues("deleteVulns", "true").Inc()
	gcDuration.WithLabelValues("deleteVulns").Observe(time.Since(start).Seconds())

	return nil
}

func enrichmentCleanup(ctx context.Context, pool *pgxpool.Pool, updater string) error {
	const (
		deleteOrphanedEnrichments = `
DELETE FROM enrichment e1 USING
	enrichment e2
	LEFT JOIN uo_enrich uen
		ON e2.id = uen.enrich
	WHERE uen.enrich IS NULL
	AND e2.updater = $1
	AND e1.id = e2.id;
`
	)

	start := time.Now()
	slog.DebugContext(ctx, "starting enrichment clean up")
	res, err := pool.Exec(ctx, deleteOrphanedEnrichments, updater)
	if err != nil {
		gcCounter.WithLabelValues("deleteEnrichments", "false").Inc()
		return fmt.Errorf("failed while exec'ing enrichment delete: %w", err)
	}
	slog.DebugContext(ctx, "enrichments deleted", "rows affected", res.RowsAffected())
	gcCounter.WithLabelValues("deleteEnrichments", "true").Inc()
	gcDuration.WithLabelValues("deleteEnrichments").Observe(time.Since(start).Seconds())

	return nil
}
