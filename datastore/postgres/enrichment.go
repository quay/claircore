package postgres

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	// analyzeEveryNRecords controls how frequently we refresh planner statistics
	// during large bulk inserts to avoid post-churn misestimation stalls.
	analyzeEveryNRecords = 10000
	// batchFlushThreshold controls how many queued statements are sent in one
	// pgx batch to the database.
	batchFlushThreshold = 1000
)

var (
	updateEnrichmentsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updateenrichments_total",
			Help:      "Total number of database queries issued in the UpdateEnrichments method.",
		},
		[]string{"query"},
	)
	updateEnrichmentsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updateenrichments_duration_seconds",
			Help:      "Duration of all queries issued in the UpdateEnrichments method.",
		},
		[]string{"query"},
	)
	getEnrichmentsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getenrichments_total",
			Help:      "Total number of database queries issued in the get method.",
		},
		[]string{"query", "success"},
	)
	getEnrichmentsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getenrichments_duration_seconds",
			Help:      "Duration of all queries issued in the get method.",
		},
		[]string{"query", "success"},
	)
)

func (s *MatcherStore) UpdateEnrichmentsIter(ctx context.Context, updater string, fp driver.Fingerprint, it datastore.EnrichmentIter) (uuid.UUID, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/MatcherStore.UpdateEnrichmentsIter")
	return s.updateEnrichments(ctx, updater, fp, it)
}

// UpdateEnrichments creates a new UpdateOperation, inserts the provided
// EnrichmentRecord(s), and ensures enrichments from previous updates are not
// queried by clients.
func (s *MatcherStore) UpdateEnrichments(ctx context.Context, updater string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (uuid.UUID, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/MatcherStore.UpdateEnrichments")
	enIter := func(yield func(record *driver.EnrichmentRecord, err error) bool) {
		for i := range es {
			if !yield(&es[i], nil) {
				break
			}
		}
	}
	return s.updateEnrichments(ctx, updater, fp, enIter)
}

func (s *MatcherStore) updateEnrichments(ctx context.Context, name string, fp driver.Fingerprint, it datastore.EnrichmentIter) (uuid.UUID, error) {
	const (
		create = `
INSERT
INTO
	update_operation (updater, fingerprint, kind)
VALUES
	($1, $2, 'enrichment')
RETURNING
	id, ref;`
		insert = `
INSERT
INTO
	enrichment (hash_kind, hash, updater, tags, data)
VALUES
	($1, $2, $3, $4, $5)
ON CONFLICT
	(hash_kind, hash)
DO
	NOTHING;`
		assoc = `
INSERT
INTO
	uo_enrich (enrich, updater, uo, date)
VALUES
	(
		(
			SELECT
				id
			FROM
				enrichment
			WHERE
				hash_kind = $1
				AND hash = $2
		),
		$3,
		$4,
		transaction_timestamp()
	)
ON CONFLICT
DO
	NOTHING;`
		refreshView = `REFRESH MATERIALIZED VIEW CONCURRENTLY latest_update_operations;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/UpdateEnrichments")

	var id uint64
	var ref uuid.UUID
	var enCt int

	err := s.pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		start := time.Now()
		if err := s.pool.QueryRow(ctx, create, name, string(fp)).Scan(&id, &ref); err != nil {
			return err
		}
		updateEnrichmentsCounter.WithLabelValues("create").Add(1)
		updateEnrichmentsDuration.WithLabelValues("create").Observe(time.Since(start).Seconds())
		zlog.Debug(ctx).
			Str("ref", ref.String()).
			Msg("update_operation created")
		return nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		var batch pgx.Batch
		flush := func() (err error) {
			err = tx.SendBatch(ctx, &batch).Close()
			clear(batch.QueuedQueries)
			batch.QueuedQueries = batch.QueuedQueries[:0]
			return err
		}
		start := time.Now()

		defer func() {
			updateEnrichmentsCounter.WithLabelValues("insert_batch").Add(1)
			updateEnrichmentsDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())
		}()
		it(func(en *driver.EnrichmentRecord, iterErr error) bool {
			if iterErr != nil {
				err = iterErr
				return false
			}
			enCt++

			// Periodically refresh planner statistics during bulk inserts to avoid stalls
			if enCt%analyzeEveryNRecords == 0 {
				if _, analyzeErr := s.pool.Exec(ctx, "ANALYZE enrichment"); analyzeErr != nil {
					zlog.Warn(ctx).Err(analyzeErr).Int("record_count", enCt).Msg("failed to analyze enrichment table during processing")
				}
			}

			hashKind, hash := hashEnrichment(en)
			batch.Queue(insert, hashKind, hash, name, en.Tags, en.Enrichment)
			batch.Queue(assoc, hashKind, hash, name, id)

			if ct := batch.Len(); ct > batchFlushThreshold {
				if err = flush(); err != nil {
					err = fmt.Errorf("failed batching: %w", err)
					return false
				}
			}

			return true
		})
		if err != nil {
			return fmt.Errorf("iterating on enrichments: %w", err)
		}
		return flush()
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed batch enrichment insert: %w", err)
	}

	if _, err = s.pool.Exec(ctx, "ANALYZE enrichment"); err != nil {
		return uuid.Nil, fmt.Errorf("could not ANALYZE enrichment: %w", err)
	}

	if _, err = s.pool.Exec(ctx, refreshView); err != nil {
		return uuid.Nil, fmt.Errorf("could not refresh latest_update_operations: %w", err)
	}
	zlog.Debug(ctx).
		Stringer("ref", ref).
		Int("inserted", enCt).
		Msg("update_operation committed")
	return ref, nil
}

func hashEnrichment(r *driver.EnrichmentRecord) (k string, d []byte) {
	h := md5.New()
	sort.Strings(r.Tags)
	for _, t := range r.Tags {
		io.WriteString(h, t)
		h.Write([]byte("\x00"))
	}
	h.Write(r.Enrichment)
	return "md5", h.Sum(nil)
}

func (s *MatcherStore) GetEnrichment(ctx context.Context, name string, tags []string) (res []driver.EnrichmentRecord, err error) {
	const query = `
SELECT
	e.tags, e.data
FROM
	uo_enrich AS uo
JOIN
	enrichment AS e
	ON (uo.enrich = e.id)
JOIN
	update_operation AS op
	ON (uo.uo = op.id)
WHERE
	op.updater = $1
	AND op.kind = 'enrichment'
	AND e.tags && $2::text[]
ORDER BY
	op.id DESC
LIMIT 1;`

	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/GetEnrichment")
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		getEnrichmentsDuration.WithLabelValues("query", strconv.FormatBool(errors.Is(err, nil))).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer func() {
		getEnrichmentsCounter.WithLabelValues("query", strconv.FormatBool(errors.Is(err, nil))).Inc()
	}()
	var (
		c    *pgxpool.Conn
		rows pgx.Rows
	)
	c, err = s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Release()
	res = make([]driver.EnrichmentRecord, 0, 8) // Guess at capacity.
	rows, err = c.Query(ctx, query, name, tags)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		i := len(res)
		res = append(res, driver.EnrichmentRecord{})
		r := &res[i]
		err = rows.Scan(&r.Tags, &r.Enrichment)
		if err != nil {
			return nil, err
		}
	}
	err = rows.Err()
	return res, err
}
