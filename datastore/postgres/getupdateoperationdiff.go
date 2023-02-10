package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	getUpdateDiffCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdatediff_total",
			Help:      "Total number of database queries issued in the GetUpdateDiff method.",
		},
		[]string{"query"},
	)
	getUpdateDiffDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdatediff_duration_seconds",
			Help:      "The duration of all queries issued in the GetUpdateDiff method",
		},
		[]string{"query"},
	)
	populateRefsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "populaterefs_total",
			Help:      "Total number of database queries issued in the populateRefs method.",
		},
		[]string{"query"},
	)
	populateRefsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "populaterefs_duration_seconds",
			Help:      "The duration of all queries issued in the populateRefs method",
		},
		[]string{"query"},
	)
)

func (s *MatcherStore) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	const (
		op = `datastore/postgres/MatcherStore.GetUpdateDiff`
		// confirmRefs will return a row only if both refs are kind = 'vulnerability'
		// therefore, if a pgx.ErrNoRows is returned from this query, at least one
		// of the incoming refs is not of kind = 'vulnerability'.
		confirmRefs = `
SELECT 1
WHERE ROW ('vulnerability') = ALL (SELECT kind FROM update_operation WHERE ref = $1 OR ref = $2);
`
		// Query takes two update IDs and returns rows that only exist in first
		// argument's set of vulnerabilities.
		query = `WITH
		lhs AS (SELECT id, updater FROM update_operation WHERE ref = $1),
		rhs AS (SELECT id, updater  FROM update_operation WHERE ref = $2)
	SELECT
		id,
		name,
		updater,
		description,
		issued,
		links,
		severity,
		normalized_severity,
		package_name,
		package_version,
		package_module,
		package_arch,
		package_kind,
		dist_id,
		dist_name,
		dist_version,
		dist_version_code_name,
		dist_version_id,
		dist_arch,
		dist_cpe,
		dist_pretty_name,
		arch_operation,
		repo_name,
		repo_key,
		repo_uri,
		fixed_in_version
	FROM vuln
	WHERE
		vuln.id IN (
			SELECT vuln AS id FROM uo_vuln JOIN lhs ON (uo_vuln.uo = lhs.id)
			EXCEPT ALL
			SELECT vuln AS id FROM uo_vuln JOIN rhs ON (uo_vuln.uo = rhs.id)
		)
		AND (
			vuln.updater = (SELECT updater FROM rhs)
			OR  vuln.updater = (SELECT updater FROM lhs)
		);
`
	)

	if cur == uuid.Nil {
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrPrecondition,
			Message: `nil uuid is invalid as "current" endpoint`,
		}
	}

	// confirm both refs are of type == 'vulnerability'
	if err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) (err error) {
		defer prometheus.NewTimer(getUpdateDiffDuration.WithLabelValues("confirmRefs")).ObserveDuration()
		defer getUpdateDiffCounter.WithLabelValues("confirmRefs").Add(1)
		var x int64
		err = c.QueryRow(ctx, confirmRefs, cur, prev).Scan(&x)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrNoRows):
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrPrecondition,
				Message: "provided ref was not of kind 'vulnerability'",
				Inner:   err,
			}
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to confirm update op ref types",
				Inner:   err,
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var err error

	// Retrieve added first.
	var diff driver.UpdateDiff
	err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) (err error) {
		const query = `SELECT updater, fingerprint, date FROM update_operation WHERE ref = $1;`

		diff.Cur.Ref = cur
		start := time.Now()
		err = c.QueryRow(ctx, query, cur).Scan(
			&diff.Cur.Updater,
			&diff.Cur.Fingerprint,
			&diff.Cur.Date,
		)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrPrecondition,
				Message: "operation does not exist",
				Inner:   err,
			}
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to deserialize current UpdateOperation",
				Inner:   err,
			}
		}
		populateRefsCounter.WithLabelValues("query").Add(1)
		populateRefsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

		if prev == uuid.Nil {
			return nil
		}
		diff.Prev.Ref = prev

		start = time.Now()
		err = c.QueryRow(ctx, query, prev).Scan(
			&diff.Prev.Updater,
			&diff.Prev.Fingerprint,
			&diff.Prev.Date,
		)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrPrecondition,
				Message: "operation does not exist",
				Inner:   err,
			}
		default:
			return &claircore.Error{
				Op:      op,
				Kind:    claircore.ErrInternal,
				Message: "failed to deserialize previous UpdateOperation",
				Inner:   err,
			}
		}
		populateRefsCounter.WithLabelValues("query").Add(1)
		populateRefsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

		return nil
	})
	if err != nil {
		return nil, err
	}

	eg, ctx := errgroup.WithContext(ctx)
	populate := func(a, b uuid.UUID, into *[]claircore.Vulnerability) func() error {
		return func() (err error) {
			// If we're starting at the beginning of time, nothing is going to
			// be removed.
			if a == uuid.Nil {
				return nil
			}
			err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) (err error) {
				defer getUpdateDiffCounter.WithLabelValues("query").Inc()
				defer prometheus.NewTimer(getUpdateDiffDuration.WithLabelValues("query")).ObserveDuration()
				rows, err := c.Query(ctx, query, a, b)
				if err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: "error querying operation diff",
						Inner:   err,
					}
				}
				defer rows.Close()
				for rows.Next() {
					i := len(*into)
					*into = append(*into, claircore.Vulnerability{
						Package: &claircore.Package{},
						Dist:    &claircore.Distribution{},
						Repo:    &claircore.Repository{},
					})
					if err := scanVulnerability(&(*into)[i], rows); err != nil {
						return &claircore.Error{
							Op:      op,
							Kind:    claircore.ErrInternal,
							Message: "failed to deserialize vulnerability",
							Inner:   err,
						}
					}
				}
				if err := rows.Err(); err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: "error while reading",
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
	}
	eg.Go(populate(cur, prev, &diff.Added))
	eg.Go(populate(prev, cur, &diff.Removed))
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return &diff, nil
}
