package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx"
	"github.com/quay/claircore"
)

const (
	selectTombstone    = `SELECT tombstone FROM updatecursor WHERE updater = $1`
	upsertUpdateCurosr = `INSERT INTO updatecursor (updater, hash, tombstone) VALUES 
							($1, $2, $3)
						  ON CONFLICT (updater) 
						  DO UPDATE SET hash = EXCLUDED.hash, tombstone = EXCLUDED.tombstone`
	deleteTombstonedVulns = `DELETE FROM vuln WHERE tombstone = $1`
	insertVulnerability   = `INSERT INTO vuln (
				  updater,
				  name,
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
				  arch,
				  fixed_in_version,
				  tombstone)
			VALUES ($1,
					$2,
					$3,
					$4,
					$5,
					$6,
					$7,
					$8,
					$9,
					$10,
					$11,
					$12,
					$13,
					$14,
					$15,
					$16)
	ON conflict (updater,
				 name,
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
				 arch,
				 fixed_in_version)
	DO UPDATE SET tombstone = EXCLUDED.tombstone;`
)

// putVulnerabilities will begin indexing the list of vulns into the database. a unique constraint
// is placed on this table to ensure deduplication. each new vulnerability is written with a new tombstone
// and each existing vulnerability has their tombstone updated. finally we delete all records with the
// told tombstone as they can be considered stale.
func putVulnerabilities(ctx context.Context, pool *pgx.ConnPool, updater string, hash string, vulns []*claircore.Vulnerability) error {
	// get old tombstone
	var oldTombstone string
	row := pool.QueryRowEx(ctx, selectTombstone, nil, updater)
	err := row.Scan(&oldTombstone)
	if err != nil {
		if err == pgx.ErrNoRows {
			oldTombstone = ""
		} else {
			return fmt.Errorf("failed to retrieve current tombstone: %v", err)
		}
	}

	// generate new tombstone
	newTombstone := uuid.New().String()

	// start a transaction
	tx, err := pool.Begin()

	// create preparted statement for batch instert
	insertVulnerabilityStmt, err := tx.Prepare("insertVulnerabilityStmt", insertVulnerability)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create insertVulnerabilty preparted statement. tx rollback: %v", err)
	}

	// begin batch insert
	batch := tx.BeginBatch()
	// use zero value structs to enforce unique constraint since postgres does not view
	// "null" as a unique field.
	for _, vuln := range vulns {
		if vuln.Package == nil {
			vuln.Package = &claircore.Package{
				Dist: &claircore.Distribution{},
			}
		}
		if vuln.Package.Dist == nil {
			vuln.Package.Dist = &claircore.Distribution{}
		}

		// queue the insert
		batch.Queue(insertVulnerabilityStmt.Name,
			[]interface{}{
				updater,
				vuln.Name,
				vuln.Description,
				vuln.Links,
				vuln.Severity,
				vuln.Package.Name,
				vuln.Package.Version,
				vuln.Package.Kind,
				vuln.Package.Dist.DID,
				vuln.Package.Dist.Name,
				vuln.Package.Dist.Version,
				vuln.Package.Dist.VersionCodeName,
				vuln.Package.Dist.VersionID,
				vuln.Package.Dist.Arch,
				vuln.FixedInVersion,
				newTombstone,
			},
			nil,
			nil,
		)
	}

	// allow up to 30 seconds for batch.Send() to complete. see warning:
	// https://godoc.org/github.com/jackc/pgx#Batch.Send
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = batch.Send(ctx, nil)
	if err != nil {
		batch.Close()
		tx.Rollback()
		return fmt.Errorf("failed to send batch vulnerability insert. tx rollback: %v", err)
	}

	err = batch.Close()
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to close batch. tx rollback: %v", err)
	}

	// delete any stale records. if oldTombstone is emptry string this indicates it's
	// our first update and nothiing to delete
	if oldTombstone != "" {
		_, err := tx.Exec(deleteTombstonedVulns, oldTombstone)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to remove tombstoned records. tx rollback: %v", err)
		}
	}

	// upsert new updatecursor
	_, err = tx.Exec(upsertUpdateCurosr, updater, hash, newTombstone)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update updatecursor. tx rollback: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}
