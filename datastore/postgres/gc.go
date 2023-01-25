package postgres

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
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
	const op = `datastore/postgres/MatcherStore.GC`
	ctx = zlog.ContextWithValues(ctx, "component", op)
	// Obtain update operations which need deleting.
	var ops []uuid.UUID
	err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) (err error) {
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
		defer prometheus.NewTimer(gcDuration.WithLabelValues("updateOps")).ObserveDuration()
		defer func() {
			gcCounter.WithLabelValues("updateOps", strconv.FormatBool(errors.Is(err, nil))).Inc()
		}()

		// Gather any update operations exceeding our keep value.
		// "Keep+1" is used because PG's array slicing is inclusive, we want to grab
		// all items once after our keep value.
		rows, err := c.Query(ctx, updateOps, keep+1, keep)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error querying for update operations",
				Inner:   err,
			}
		}
		defer rows.Close()
		for rows.Next() {
			// pgx will not scan directly into a []uuid.UUID
			tmp := pgtype.UUIDArray{}
			err = rows.Scan(&tmp)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "error deserializing UUIDs",
					Inner:   err,
				}
			}
			for _, u := range tmp.Elements {
				ops = append(ops, u.Bytes) // this works since [16]byte value is assignable to uuid.UUID
			}
		}
		if err = rows.Err(); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error processing update operation rows",
				Inner:   err,
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(ops) == 0 {
		return 0, nil
	}

	// Delete em', but not too many...
	if len(ops) >= GCThrottle {
		ops = ops[:GCThrottle]
	}
	deletedOps, err := s.DeleteUpdateOperations(ctx, ops...)
	rem := int64(len(ops)) - deletedOps
	if err != nil {
		return rem, err
	}

	// Get all updaters we know about.
	var updaters []string
	err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) (err error) {
		// will always contain at least two update operations
		const selectUpdaters = `SELECT DISTINCT(updater) FROM update_operation;`
		defer prometheus.NewTimer(gcDuration.WithLabelValues("selectUpdaters")).ObserveDuration()
		defer func() {
			gcCounter.WithLabelValues("selectUpdaters", strconv.FormatBool(errors.Is(err, nil))).Inc()
		}()
		rows, err := c.Query(ctx, selectUpdaters)
		if err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error selecting distinct updaters",
				Inner:   err,
			}
		}
		defer rows.Close()

		for rows.Next() {
			var updater string
			err = rows.Scan(&updater)
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "error deserializing updater",
					Inner:   err,
				}
			}
			updaters = append(updaters, updater)
		}
		if err = rows.Err(); err != nil {
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "error processing updater rows",
				Inner:   err,
			}
		}
		return nil
	})
	if err != nil {
		return rem, err
	}

	// Issue concurrent updater-based deletion for known updaters.
	// Limit concurrency by available goroutines.
	sem := semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)))
	errC := make(chan error, len(updaters))
	var wg sync.WaitGroup
	cleanup := func(updater string) {
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
		ctx = zlog.ContextWithValues(ctx, "updater", updater)
		defer wg.Done()
		err := sem.Acquire(ctx, 1)
		if err != nil {
			// Documented to only return ctx.Err() (Context is done) or nil.
			return
		}
		defer sem.Release(1)
		defer prometheus.NewTimer(gcDuration.WithLabelValues("deleteOrphanedVulns")).ObserveDuration()
		defer func() {
			gcCounter.WithLabelValues("deleteOrphanedVulns", strconv.FormatBool(errors.Is(err, nil))).Inc()
		}()

		zlog.Debug(ctx).
			Msg("starting clean up")
		res, err := s.pool.Exec(ctx, deleteOrphanedVulns, updater)
		if err != nil {
			errC <- err
		}
		zlog.Debug(ctx).
			Int64("rows affected", res.RowsAffected()).
			Bool("success", errors.Is(err, nil)).
			Msg("vulns deleted")
	}

	wg.Add(len(updaters))
	for _, updater := range updaters {
		go cleanup(updater)
	}
	wg.Wait()
	close(errC)

	if len(errC) > 0 {
		join := false
		b := strings.Builder{}
		for e := range errC {
			if join {
				b.WriteString("; ")
			}
			b.WriteString(e.Error())
			join = true
		}
		return rem, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrInternal,
			Message: "errors during gc:",
			Inner:   errors.New(b.String()),
		}
	}
	return rem, nil
}
