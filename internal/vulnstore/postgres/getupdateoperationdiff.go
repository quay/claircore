package postgres

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	// selectUpdateOperation retrieves an
	// Update Operation
	selectUpdatOperation = `
	SELECT id, updater, fingerprint, date 
	FROM update_operation
	WHERE id = $1;
	`
	// diffRemovedCTE will return vulnerabilities present in
	// UOID_B but not UOID_A. Since A is always applied to
	// B this signifies removed vulnerabilities
	diffRemovedCTE = `
	WITH update_a AS (
		SELECT (hash)
		FROM vuln
		WHERE vuln.uo_id = $1
	),
		 update_b AS (
			 SELECT *
			 FROM vuln
			 WHERE vuln.uo_id = $2
		 )
	SELECT b.id,
		   b.name,
		   b.updater,
		   b.description,
		   b.links,
		   b.severity,
		   b.package_name,
		   b.package_version,
		   b.package_kind,
		   b.dist_id,
		   b.dist_name,
		   b.dist_version,
		   b.dist_version_code_name,
		   b.dist_version_id,
		   b.dist_arch,
		   b.dist_cpe,
		   b.dist_pretty_name,
		   b.repo_name,
		   b.repo_key,
		   b.repo_uri
	FROM update_b b
	WHERE b.hash NOT IN (SELECT a.hash FROM update_a a);
	`
	// diffAddedCTE will return vulnerabilities present in
	// UOID_A but not UOID_B. Since A is always applied to B
	// this signifies added vulnerabilities
	diffAddedCTE = `
	WITH update_a AS (
		SELECT *
		FROM vuln
		WHERE vuln.uo_id = $1
	),
		 update_b AS (
			 SELECT (hash)
			 FROM vuln
			 WHERE vuln.uo_id = $2
		 )
	SELECT a.id,
		   a.name,
		   a.updater,
		   a.description,
		   a.links,
		   a.severity,
		   a.package_name,
		   a.package_version,
		   a.package_kind,
		   a.dist_id,
		   a.dist_name,
		   a.dist_version,
		   a.dist_version_code_name,
		   a.dist_version_id,
		   a.dist_arch,
		   a.dist_cpe,
		   a.dist_pretty_name,
		   a.repo_name,
		   a.repo_key,
		   a.repo_uri
	FROM update_a a
	WHERE a.hash NOT IN (SELECT b.hash FROM update_b b);
	`
)

func getUpdateOperationDiff(ctx context.Context, pool *pgxpool.Pool, UOID_A, UOID_B string) (*driver.UpdateDiff, error) {
	var a, b driver.UpdateOperation
	// retrieve UpdateOperation A
	err := func() error {
		row := pool.QueryRow(ctx, selectUpdatOperation, UOID_A)
		err := row.Scan(
			&a.ID,
			&a.Updater,
			&a.Fingerprint,
			&a.Date,
		)
		switch {
		case err == pgx.ErrNoRows:
			return fmt.Errorf("UOID_A %v does not exist", UOID_A)
		case err != nil:
			return fmt.Errorf("failed to scan UpdateOperation A: %w", err)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	// retrieve UpdateOperation B
	err = func() error {
		row := pool.QueryRow(ctx, selectUpdatOperation, UOID_B)
		err = row.Scan(
			&b.ID,
			&b.Updater,
			&b.Fingerprint,
			&b.Date,
		)
		switch {
		case err == pgx.ErrNoRows:
			return fmt.Errorf("UOID_A %v does not exist", UOID_B)
		case err != nil:
			return fmt.Errorf("failed to scan UpdateOperation B: %w", err)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	// retrieve UpdateOperation B
	diff := &driver.UpdateDiff{
		A:       a,
		B:       b,
		Added:   []*claircore.Vulnerability{},
		Removed: []*claircore.Vulnerability{},
	}

	// retrieve added vulnerabilities
	err = func() error {
		rows, err := pool.Query(ctx, diffAddedCTE, UOID_A, UOID_B)
		defer rows.Close()
		if err != nil {
			return fmt.Errorf("failed to retrive added vulnerabilities: %w", err)
		}
		for rows.Next() {
			v := claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}
			var id uint64
			err := rows.Scan(
				&id,
				&v.Name,
				&v.Updater,
				&v.Description,
				&v.Links,
				&v.Severity,
				&v.Package.Name,
				&v.Package.Version,
				&v.Package.Kind,
				&v.Dist.DID,
				&v.Dist.Name,
				&v.Dist.Version,
				&v.Dist.VersionCodeName,
				&v.Dist.VersionID,
				&v.Dist.Arch,
				&v.Dist.CPE,
				&v.Dist.PrettyName,
				&v.Repo.Name,
				&v.Repo.Key,
				&v.Repo.URI,
			)
			v.ID = strconv.FormatUint(id, 10)
			if err != nil {
				return fmt.Errorf("failed to scan added vulnerability: %v", err)
			}
			diff.Added = append(diff.Added, &v)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	// retrieve removed vulnerabilities
	err = func() error {
		rows, err := pool.Query(ctx, diffRemovedCTE, UOID_A, UOID_B)
		defer rows.Close()
		if err != nil {
			return fmt.Errorf("failed to retrive added vulnerabilities: %w", err)
		}
		for rows.Next() {
			v := claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}
			var id uint64
			err := rows.Scan(
				&id,
				&v.Name,
				&v.Updater,
				&v.Description,
				&v.Links,
				&v.Severity,
				&v.Package.Name,
				&v.Package.Version,
				&v.Package.Kind,
				&v.Dist.DID,
				&v.Dist.Name,
				&v.Dist.Version,
				&v.Dist.VersionCodeName,
				&v.Dist.VersionID,
				&v.Dist.Arch,
				&v.Dist.CPE,
				&v.Dist.PrettyName,
				&v.Repo.Name,
				&v.Repo.Key,
				&v.Repo.URI,
			)
			v.ID = strconv.FormatUint(id, 10)
			if err != nil {
				return fmt.Errorf("failed to scan removed vulnerability: %v", err)
			}
			diff.Removed = append(diff.Removed, &v)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	return diff, nil
}
