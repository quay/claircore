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
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/microbatch"
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

// UpdateEnrichments creates a new UpdateOperation, inserts the provided
// EnrichmentRecord(s), and ensures enrichments from previous updates are not
// queried by clients.
func (s *MatcherStore) UpdateEnrichments(ctx context.Context, name string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (uuid.UUID, error) {
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
				AND updater = $3
		),
		$3,
		$4,
		transaction_timestamp()
	)
ON CONFLICT
DO
	NOTHING;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/UpdateEnrichments")

	var id uint64
	var ref uuid.UUID

	start := time.Now()

	if err := s.pool.QueryRow(ctx, create, name, string(fp)).Scan(&id, &ref); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}

	updateEnrichmentsCounter.WithLabelValues("create").Add(1)
	updateEnrichmentsDuration.WithLabelValues("create").Observe(time.Since(start).Seconds())

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("update_operation created")

	batch := microbatch.NewInsert(tx, 2000, time.Minute)
	start = time.Now()
	for i := range es {
		hashKind, hash := hashEnrichment(&es[i])
		err := batch.Queue(ctx, insert,
			hashKind, hash, name, es[i].Tags, es[i].Enrichment,
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to queue enrichment: %w", err)
		}
		if err := batch.Queue(ctx, assoc, hashKind, hash, name, id); err != nil {
			return uuid.Nil, fmt.Errorf("failed to queue association: %w", err)
		}
	}
	if err := batch.Done(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish batch enrichment insert: %w", err)
	}
	updateEnrichmentsCounter.WithLabelValues("insert_batch").Add(1)
	updateEnrichmentsDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	zlog.Debug(ctx).
		Stringer("ref", ref).
		Int("inserted", len(es)).
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
WITH
	latest
		AS (
			SELECT
				max(id) AS id
			FROM
				update_operation
			WHERE
				updater = $1
		)
SELECT
	e.tags, e.data
FROM
	enrichment AS e,
	uo_enrich AS uo,
	latest
WHERE
	uo.uo = latest.id
	AND uo.enrich = e.id
	AND e.tags && $2::text[];`

	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/GetEnrichment")
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		getEnrichmentsDuration.WithLabelValues("query", strconv.FormatBool(errors.Is(err, nil)))
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
