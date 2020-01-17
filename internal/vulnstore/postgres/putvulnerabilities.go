package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/microbatch"
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
				  dist_arch,
				  dist_cpe,
				  dist_pretty_name,
				  repo_name,
                  repo_key,
                  repo_uri,
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
					$16,
					$17,
					$18,
					$19,
					$20,
					$21)
	ON conflict (updater,
				 name,
				 md5(description),
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
				 repo_uri,
				 fixed_in_version)
	DO UPDATE SET tombstone = EXCLUDED.tombstone;`
)

// putVulnerabilities will begin indexing the list of vulns into the database. a unique constraint
// is placed on this table to ensure deduplication. each new vulnerability is written with a new tombstone
// and each existing vulnerability has their tombstone updated. finally we delete all records with the
// told tombstone as they can be considered stale.
func putVulnerabilities(ctx context.Context, pool *pgxpool.Pool, updater string, hash string, vulns []*claircore.Vulnerability) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/putVulnerabilities").
		Logger()
	ctx = log.WithContext(ctx)
	// get old tombstone
	var oldTombstone string
	row := pool.QueryRow(ctx, selectTombstone, updater)
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	skipCt := 0
	// safe sized batch inserts to postgres
	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute)
	for _, vuln := range vulns {
		if vuln.Package == nil || vuln.Package.Name == "" {
			skipCt++
			continue
		}
		if vuln.Dist == nil || vuln.Dist.Name == "" {
			skipCt++
			continue
		}
		if vuln.Repo == nil {
			vuln.Repo = &claircore.Repository{}
		}
		err := mBatcher.Queue(ctx,
			insertVulnerability,
			updater,
			vuln.Name,
			vuln.Description,
			vuln.Links,
			vuln.Severity,
			vuln.Package.Name,
			vuln.Package.Version,
			vuln.Package.Kind,
			vuln.Dist.DID,
			vuln.Dist.Name,
			vuln.Dist.Version,
			vuln.Dist.VersionCodeName,
			vuln.Dist.VersionID,
			vuln.Dist.Arch,
			vuln.Dist.CPE,
			vuln.Dist.PrettyName,
			vuln.Repo.Name,
			vuln.Repo.Key,
			vuln.Repo.URI,
			vuln.FixedInVersion,
			newTombstone,
		)
		if err != nil {
			return fmt.Errorf("failed to queue vulnerability: %v", err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("failed to finish batch vulnerability insert: %v", err)
	}

	// delete any stale records. if oldTombstone is emptry string this indicates it's
	// our first update and nothiing to delete
	if oldTombstone != "" {
		_, err := tx.Exec(ctx, deleteTombstonedVulns, oldTombstone)
		if err != nil {
			return fmt.Errorf("failed to remove tombstoned records. tx rollback: %v", err)
		}
	}

	// upsert new updatecursor
	_, err = tx.Exec(ctx, upsertUpdateCurosr, updater, hash, newTombstone)
	if err != nil {
		return fmt.Errorf("failed to update updatecursor. tx rollback: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	log.Debug().
		Int("skipped", skipCt).
		Int("inserted", len(vulns)-skipCt).
		Msg("vulnerabilities inserted")
	return nil
}
