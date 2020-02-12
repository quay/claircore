package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	// SelectUpdateOperation retrieves an UpdateOperation.
	selectUpdateOperation = `SELECT updater, fingerprint, date FROM update_operation WHERE ref = $1;`

	// DiffQuery takes two update IDs and returns rows that only exist in first
	// argument's set of vulnerabilities.
	diffQuery = `WITH
lhs AS (SELECT id FROM update_operation WHERE ref = $1),
rhs AS (SELECT id FROM update_operation WHERE ref = $2),
diff AS (
SELECT
	id,
	name,
	updater,
	description,
	links,
	severity,
	package_name,
	package_version,
	package_kind,
	dist_id,
	dist_name,
	dist_version,
	dist_version_code_name,
	dist_version_id,
	dist_arch,
	dist_cpe,
	dist_pretty_name,
	repo_name,
	repo_key,
	repo_uri
FROM vuln
WHERE
	vuln.id IN (
		SELECT vuln AS id FROM uo_vuln WHERE uo = lhs.id
		EXCEPT ALL
		SELECT vuln AS id FROM uo_vuln WHERE uo = rhs.id);`
)

func getUpdateOperationDiff(ctx context.Context, pool *pgxpool.Pool, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	if b == uuid.Nil {
		return nil, errors.New("nil uuid is an invalid endpoint")
	}
	var diff driver.UpdateDiff
	fromZero := a == uuid.Nil

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		if fromZero {
			// The nil uuid means we're starting from the beginning of time.
			return nil
		}
		// retrieve UpdateOperation A
		diff.A.Ref = a
		err := pool.QueryRow(ctx, selectUpdateOperation, a).Scan(
			&diff.A.Updater,
			&diff.A.Fingerprint,
			&diff.A.Date,
		)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("operation %v does not exist", a)
		default:
			return fmt.Errorf("failed to scan UpdateOperation a: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		// retrieve UpdateOperation B
		diff.B.Ref = b
		err := pool.QueryRow(ctx, selectUpdateOperation, b).Scan(
			&diff.B.Updater,
			&diff.B.Fingerprint,
			&diff.B.Date,
		)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("operation %v does not exist", b)
		default:
			return fmt.Errorf("failed to scan UpdateOperation b: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		// Get Vulnerabilites that only exist in operation "a", meaning they
		// were removed in any updates between "a" and "b".
		if fromZero {
			// If we're starting at the beginning of time, nothing is going to
			// be removed.
			return nil
		}
		rows, err := pool.Query(ctx, diffQuery, a, b)
		if err != nil {
			return fmt.Errorf("failed to retrieve removed vulnerabilities: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			v := claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}
			if err := scanVulnerability(&v, rows); err != nil {
				return fmt.Errorf("failed to scan removed vulnerability: %v", err)
			}
			diff.Removed = append(diff.Removed, v)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	})

	eg.Go(func() error {
		// retrieve added vulnerabilities
		rows, err := pool.Query(ctx, diffQuery, b, a)
		if err != nil {
			return fmt.Errorf("failed to retrieve added vulnerabilities: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			v := claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}
			if err := scanVulnerability(&v, rows); err != nil {
				return fmt.Errorf("failed to scan added vulnerability: %v", err)
			}
			diff.Added = append(diff.Added, v)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return &diff, nil
}
