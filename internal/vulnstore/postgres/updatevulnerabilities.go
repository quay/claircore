package postgres

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	// InsertUpdateOperation inserts a new update operation into the vulnstore.
	insertUpdateOperation = `INSERT INTO update_operation (updater, fingerprint) VALUES ($1, $2) RETURNING id;`
	// SelectNewestUpdateOperation returns the newest UpdateOperation ID for a
	// given updater.
	selectNewestUpdateOperation = `SELECT (id) FROM update_operation WHERE updater = $1 ORDER BY id DESC LIMIT 1; `

	insertVulnerability1 = `WITH
attempt AS (
	INSERT INTO vuln (
		hash_kind,
		hash,
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
		repo_uri,
		fixed_in_version
	) VALUES (
	  $1,
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
	  $21,
	  $22) 	
	ON CONFLICT (hash_kind, hash) DO NOTHING
	RETURNING id
)
INSERT INTO uo_vuln (vuln, uo) VALUES (
	COALESCE (
		(SELECT id FROM attempt),
		(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2)
	),
	$23);`
)

// UpdateVulnerabilities creates a new UpdateOperation for this update call,
// inserts the provided vulnerabilities and computes a diff comprising the
// removed and added vulnerabilities for this UpdateOperation.
func updateVulnerabilites(ctx context.Context, pool *pgxpool.Pool, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// create UpdateOperation
	var id uuid.UUID
	err = pool.QueryRow(ctx, insertUpdateOperation, updater, string(fingerprint)).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create UpdaterOperation")
	}

	// batch insert vulnerabilities
	skipCt := 0
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
		hashKind, hash := md5Vuln(vuln)
		err := mBatcher.Queue(ctx,
			insertVulnerability1,
			hashKind,
			hash,
			vuln.Name,
			vuln.Updater,
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
			id,
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to queue vulnerability: %v", err)
		}
	}
	if err := mBatcher.Done(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish batch vulnerability insert: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return id, nil
}

// Md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *claircore.Vulnerability) (string, []byte) {
	h := md5.New()
	h.Write([]byte(v.Name))
	h.Write([]byte(v.Description))
	h.Write([]byte(v.Links))
	h.Write([]byte(v.Severity))
	h.Write([]byte(v.Package.Name))
	h.Write([]byte(v.Package.Version))
	h.Write([]byte(v.Package.Kind))
	h.Write([]byte(v.Dist.DID))
	h.Write([]byte(v.Dist.Name))
	h.Write([]byte(v.Dist.Version))
	h.Write([]byte(v.Dist.VersionCodeName))
	h.Write([]byte(v.Dist.VersionID))
	h.Write([]byte(v.Dist.Arch))
	h.Write([]byte(v.Dist.CPE))
	h.Write([]byte(v.Dist.PrettyName))
	h.Write([]byte(v.Repo.Name))
	h.Write([]byte(v.Repo.Key))
	h.Write([]byte(v.Repo.URI))
	h.Write([]byte(v.FixedInVersion))
	return "md5", h.Sum(nil)
}
