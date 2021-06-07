package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/semaphore"
)

var (
	gcCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "gc_total",
			Help:      "Total number of database queries issued in the GC method.",
		},
		[]string{"query"},
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

// GC is split into two phases, first it will identify any update operations
// which are older then the provided keep value and delete these.
//
// Next it will perform chunked deletions of any vulns from the vuln table
// which are not longer referenced by update operations.
//
// The GC is throttled to not overload the database with cascade deletes.
// If a full GC is required run this method until the returned int64 value
// is 0.
func (s *Store) GC(ctx context.Context, keep int) (int64, error) {
	const (
		// GCThrottle sets a limit for the number of deleted update operations
		// (and subsequent cascade deletes in the uo_vuln table) that can occur in a GC run.
		GCThrottle = 50
	)

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

	// issue concurrent chunked deletion for known updaters
	// limit concurrency by available goroutines.
	cpus := int64(runtime.GOMAXPROCS(0))
	sem := semaphore.NewWeighted(cpus)

	errC := make(chan error, len(updaters))

	for _, updater := range updaters {
		err = sem.Acquire(ctx, 1)
		if err != nil {
			break
		}
		go func(u string) {
			defer sem.Release(1)
			err := chunkedCleanup(ctx, s.pool, u)
			if err != nil {
				errC <- err
			}
		}(updater)
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
func distinctUpdaters(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	const (
		// will always contain at least two update operations
		selectUpdaters = `
SELECT DISTINCT(updater) FROM update_operation;
`
	)
	rows, err := pool.Query(ctx, selectUpdaters)
	if err != nil {
		return nil, fmt.Errorf("error selecting distinct updaters: %v", err)
	}
	defer rows.Close()

	var updaters []string
	for rows.Next() {
		var updater string
		err := rows.Scan(&updater)
		switch err {
		case nil:
			// hop out
		default:
			return nil, fmt.Errorf("error scanning updater: %v", err)
		}
		updaters = append(updaters, updater)
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
		return nil, 0, fmt.Errorf("error querying for update operations: %v", err)
	}

	gcCounter.WithLabelValues("updateOps").Add(1)
	gcDuration.WithLabelValues("updateOps").Observe(time.Since(start).Seconds())

	defer rows.Close()
	for rows.Next() {
		// pgx will not scan directly into a []uuid.UUID
		tmp := pgtype.UUIDArray{}
		err := rows.Scan(&tmp)
		if err != nil {
			return nil, 0, fmt.Errorf("error scanning update operations: %w", err)
		}
		for _, u := range tmp.Elements {
			m = append(m, u.Bytes) // this works since [16]byte value is assignable to uuid.UUID
		}
	}
	if rows.Err() != nil {
		return nil, 0, rows.Err()
	}
	return m, int64(len(m)), nil
}

func chunkedCleanup(ctx context.Context, pool *pgxpool.Pool, updater string) error {
	const (
		paginatedSelect = `
SELECT id FROM vuln WHERE vuln.updater = $1 AND id > $2 ORDER BY id ASC LIMIT 10000;
`
		shouldDelete = `
SELECT NOT EXISTS(SELECT 1 FROM uo_vuln WHERE vuln = $1);
`
		deleteVuln = `
DELETE FROM vuln WHERE id = $1;
`
	)

	ids := make([]int64, 0, 10000)
	var largestID int64

	// loop is only terminated by returning from the function.
	for {
		// idempotently reslice for next chunk operation.
		ids = ids[:0]

		// collect ids which the provided updater created.
		// note arguments via closure
		err := func() error {
			start := time.Now()

			rows, err := pool.Query(ctx, paginatedSelect, updater, largestID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id int64
				err := rows.Scan(&id)
				if err != nil {
					return fmt.Errorf("encountered error while scanning vuln id: %v", err)
				}
				ids = append(ids, id)
			}
			if rows.Err() != nil {
				return rows.Err()
			}

			gcCounter.WithLabelValues("paginatedSelect").Add(1)
			gcDuration.WithLabelValues("paginatedSelect").Observe(time.Since(start).Seconds())
			return nil
		}()
		if err != nil {
			return fmt.Errorf("failed to collect vuln ids for updater %v: %v", updater, err)
		}

		// if the ids array is empty we processed all
		// vulns, we terminate the entire function here.
		if len(ids) == 0 {
			return nil
		}

		// keep track of largest id for next paginated request.
		largestID = ids[len(ids)-1]

		// cross reference uo_vuln table to determine which ids should be
		// deleted. these operations are small and fast so batching is optimal.
		// note arguments via closure
		//
		// a new batch is returned containing, if any, delete queries to run.
		toDelete, err := func() (*pgx.Batch, error) {
			b := &pgx.Batch{}
			toDelete := &pgx.Batch{}

			for _, id := range ids {
				b.Queue(shouldDelete, id)
			}

			start := time.Now()
			res := pool.SendBatch(ctx, b)
			defer res.Close()

			var do bool
			for i := 0; i < b.Len(); i++ {
				err = res.QueryRow().Scan(&do)
				if err != nil {
					return nil, fmt.Errorf("failed while scanning existence check boolean: %v", err)
				}
				if do {
					toDelete.Queue(deleteVuln, ids[i])
				}
			}

			gcCounter.WithLabelValues("shoulddelete_batch").Add(1)
			gcDuration.WithLabelValues("shoulddelete_batch").Observe(time.Since(start).Seconds())

			return toDelete, nil
		}()
		if err != nil {
			return err
		}

		// perform the delete branch
		// note arguments via closure
		err = func() error {
			if toDelete.Len() == 0 {
				return nil
			}

			start := time.Now()
			res := pool.SendBatch(ctx, toDelete)
			defer res.Close()

			for i := 0; i < toDelete.Len(); i++ {
				_, err := res.Exec()
				if err != nil {
					return fmt.Errorf("failed while exec'ing vuln delete: %v", err)
				}
			}
			gcCounter.WithLabelValues("deletevuln_batch").Add(1)
			gcDuration.WithLabelValues("deletevuln_batch").Observe(time.Since(start).Seconds())
			return nil
		}()
		if err != nil {
			return err
		}
	}
}
