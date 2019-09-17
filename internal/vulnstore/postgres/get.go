package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

func get(ctx context.Context, pool *pgx.ConnPool, packages []*claircore.Package, opts vulnstore.GetOpts) (map[int][]*claircore.Vulnerability, error) {
	// build our query we will make into a prepared statement. see build func definition for details and context
	query, dedupedMatchers, err := getBuilder(opts.Matchers)

	// create a prepared statement
	tx, err := pool.BeginEx(ctx, nil)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	getStmt, err := tx.Prepare("getStmt", query)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// start a batch
	batch := tx.BeginBatch()

	// create our bind arguments. the order of dedupedMatchers
	// dictates the order of our bindvar values.
	for _, pkg := range packages {
		args := []interface{}{}
		for _, m := range dedupedMatchers {
			switch m {
			case driver.PackageDistributionDID:
				args = append(args, pkg.Dist.DID)
			case driver.PackageDistributionName:
				args = append(args, pkg.Dist.Name)
			case driver.PackageDistributionVersion:
				args = append(args, pkg.Dist.Version)
			case driver.PackageDistributionVersionCodeName:
				args = append(args, pkg.Dist.VersionCodeName)
			case driver.PackageDistributionVersionID:
				args = append(args, pkg.Dist.VersionID)
			case driver.PackageDistributionArch:
				args = append(args, pkg.Dist.Arch)
			}
		}
		// fills the OR bind vars for (package_name = binary_package OR package_name = source_package)
		args = append(args, pkg.Source.Name)
		args = append(args, pkg.Name)

		// queue the select query
		batch.Queue(getStmt.Name, args, nil, nil)
	}
	// send the batch
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch.Send(ctx, nil)

	// gather all the returned vulns for each queued select statement
	results := make(map[int][]*claircore.Vulnerability)
	for _, pkg := range packages {
		rows, err := batch.QueryResults()
		if err != nil {
			batch.Close()
			tx.Rollback()
			return nil, err
		}

		// unpack all returned rows into claircore.Vulnerability structs
		for rows.Next() {
			// fully allocate vuln struct
			v := &claircore.Vulnerability{
				Package: &claircore.Package{
					Dist: &claircore.Distribution{},
				},
			}

			err := rows.Scan(
				&v.ID,
				&v.Name,
				&v.Description,
				&v.Links,
				&v.Severity,
				&v.Package.Name,
				&v.Package.Version,
				&v.Package.Kind,
				&v.Package.Dist.DID,
				&v.Package.Dist.Name,
				&v.Package.Dist.Version,
				&v.Package.Dist.VersionCodeName,
				&v.Package.Dist.VersionID,
				&v.Package.Dist.Arch,
				&v.FixedInVersion,
			)
			if err != nil {
				batch.Close()
				tx.Rollback()
				return nil, fmt.Errorf("failed to scan vulnerability")
			}

			// add vulernability to result. handle if array does not exist
			if _, ok := results[pkg.ID]; !ok {
				vvulns := []*claircore.Vulnerability{v}
				results[pkg.ID] = vvulns
			} else {
				results[pkg.ID] = append(results[pkg.ID], v)
			}
		}
	}

	err = batch.Close()
	if err != nil {
		batch.Close()
		tx.Rollback()
		return nil, fmt.Errorf("failed to close batch: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}

	return results, nil
}
