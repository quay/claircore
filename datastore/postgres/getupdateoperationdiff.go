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

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	getUpdateDiffCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdatediff_total",
			Help:      "Total number of database queries issued in the getUpdateDiff  method.",
		},
		[]string{"query"},
	)
	getUpdateDiffDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getupdatediff_duration_seconds",
			Help:      "The duration of all queries issued in the getUpdateDiff method",
		},
		[]string{"query"},
	)
	populateRefsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "populaterefs_total",
			Help:      "Total number of database queries issued in the populateRefs  method.",
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
	// confirmRefs will return a row only if both refs are kind = 'vulnerability'
	// therefore, if a pgx.ErrNoRows is returned from this query, at least one
	// of the incoming refs is not of kind = 'vulnerability'.
	const confirmRefs = `
SELECT 1
WHERE ROW ('vulnerability') = ALL (SELECT kind FROM update_operation WHERE ref = $1 OR ref = $2);
`
	// Query takes two update IDs and returns rows that only exist in first
	// argument's set of vulnerabilities.
	const query = `WITH
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

	if cur == uuid.Nil {
		return nil, errors.New("nil uuid is invalid as \"current\" endpoint")
	}

	// confirm both refs are of type == 'vulnerability'
	start := time.Now()
	rows, err := s.pool.Query(ctx, confirmRefs, cur, prev)
	switch err {
	case nil:
		rows.Close()
	case pgx.ErrNoRows:
		return nil, fmt.Errorf("provided ref was not of kind 'vulnerability'")
	default:
		return nil, fmt.Errorf("failed to confirm update op ref types: %w", err)
	}
	getUpdateDiffCounter.WithLabelValues("confirmrefs").Add(1)
	getUpdateDiffDuration.WithLabelValues("confirmrefs").Observe(time.Since(start).Seconds())

	// Retrieve added first.
	var diff driver.UpdateDiff
	if err := populateRefs(ctx, &diff, s.pool, prev, cur); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, query, cur, prev)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve added vulnerabilities: %w", err)
	}

	getUpdateDiffCounter.WithLabelValues("query").Add(1)
	getUpdateDiffDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	defer rows.Close()

	for rows.Next() {
		v := claircore.Vulnerability{
			Package: &claircore.Package{},
			Dist:    &claircore.Distribution{},
			Repo:    &claircore.Repository{},
		}
		if err := scanVulnerability(&v, rows); err != nil {
			return nil, fmt.Errorf("failed to scan added vulnerability: %v", err)
		}
		diff.Added = append(diff.Added, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close() // OK according to the docs.

	// If we're starting at the beginning of time, nothing is going to
	// be removed.
	if prev == uuid.Nil {
		return &diff, nil
	}
	rows, err = s.pool.Query(ctx, query, prev, cur)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve removed vulnerabilities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		v := claircore.Vulnerability{
			Package: &claircore.Package{},
			Dist:    &claircore.Distribution{},
			Repo:    &claircore.Repository{},
		}
		if err := scanVulnerability(&v, rows); err != nil {
			return nil, fmt.Errorf("failed to scan removed vulnerability: %v", err)
		}
		diff.Removed = append(diff.Removed, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &diff, nil
}

// PopulateRefs fills in the provided UpdateDiff with the details of the
// operations indicated by the two refs.
func populateRefs(ctx context.Context, diff *driver.UpdateDiff, pool *pgxpool.Pool, prev, cur uuid.UUID) error {
	const query = `SELECT updater, fingerprint, date FROM update_operation WHERE ref = $1;`
	var err error

	diff.Cur.Ref = cur
	start := time.Now()
	err = pool.QueryRow(ctx, query, cur).Scan(
		&diff.Cur.Updater,
		&diff.Cur.Fingerprint,
		&diff.Cur.Date,
	)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("operation %v does not exist", cur)
	default:
		return fmt.Errorf("failed to scan current UpdateOperation: %w", err)
	}
	populateRefsCounter.WithLabelValues("query").Add(1)
	populateRefsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	if prev == uuid.Nil {
		return nil
	}
	diff.Prev.Ref = prev

	start = time.Now()
	err = pool.QueryRow(ctx, query, prev).Scan(
		&diff.Prev.Updater,
		&diff.Prev.Fingerprint,
		&diff.Prev.Date,
	)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("operation %v does not exist", prev)
	default:
		return fmt.Errorf("failed to scan previous UpdateOperation: %w", err)
	}
	populateRefsCounter.WithLabelValues("query").Add(1)
	populateRefsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}
