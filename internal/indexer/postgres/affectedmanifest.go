package postgres

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/omnimatcher"
)

// affectedManifests finds the manifests digests which are affected by the provided vulnerability.
//
// an exhaustive search for all indexed packages of the same name as the vulnerability is performed.
//
// the list of packages is filtered down to only the affected set.
//
// the manifest index is then queried to resolve a list of manifest hashes containing the affected
// artifacts.
func affectedManifests(ctx context.Context, pool *pgxpool.Pool, v claircore.Vulnerability) ([]claircore.Digest, error) {
	const (
		selectPackages = `
		SELECT id, name, version, kind
		FROM package
		WHERE name = $1;
		`
		selectAffected = `
		SELECT manifest_hash
		FROM manifest_index
		WHERE package_id = $1
		  AND (
			CASE
				WHEN $2::bigint IS NULL THEN
					dist_id IS NULL
				ELSE
					dist_id = $2
				END
			)
		  AND (
			CASE
				WHEN $3::bigint IS NULL THEN
					repo_id IS NULL
				ELSE
					repo_id = $3
				END
			);
		`
	)
	log := zerolog.Ctx(ctx).
		With().
		Str("component", "internal/indexer/postgres/affectedManifests").
		Logger()

	// confirm the incoming vuln can be
	// resolved into a prototype index record
	pr, err := protoRecord(ctx, pool, v)
	if err != nil {
		return nil, err
	}

	// collect all packages which may be affected
	// by the vulnerability in question.
	pkgsToFilter := []claircore.Package{}
	rows, err := pool.Query(ctx, selectPackages, v.Package.Name)
	if err != nil {
		rows.Close()
		if err == pgx.ErrNoRows {
			return []claircore.Digest{}, nil
		}
		return nil, fmt.Errorf("failed to query packages associated with vulnerablility %+v: %v", v, err)
	}
	for rows.Next() {
		var pkg claircore.Package
		var id int64
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Version,
			&pkg.Kind,
		)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan package: %v", err)
		}
		idStr := strconv.FormatInt(id, 10)
		pkg.ID = idStr
		pkgsToFilter = append(pkgsToFilter, pkg)
	}
	log.Debug().Int("count", len(pkgsToFilter)).Msg("packages to filter")

	// for each package discovered create an index record
	// and determine if any in-tree matcher finds the record vulnerable
	var filteredRecords []claircore.IndexRecord
	om := omnimatcher.New(nil)
	for _, pkg := range pkgsToFilter {
		pr.Package = &pkg
		if om.Vulnerable(&pr, &v) {
			p := pkg // make a copy, or else you'll get a stale reference later
			filteredRecords = append(filteredRecords, claircore.IndexRecord{
				Package:      &p,
				Distribution: pr.Distribution,
				Repository:   pr.Repository,
			})
		}
	}
	log.Debug().Int("count", len(filteredRecords)).Msg("vulnerable indexrecords")

	// query the manifest index for manifests containing
	// the vulnerable indexrecords and create a set
	// containing each unique manifest
	set := map[string]claircore.Digest{}
	for _, record := range filteredRecords {
		v, err := toValues(record)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve record %+v to sql values for query: %v", record, err)
		}

		rows, err := pool.Query(ctx,
			selectAffected,
			record.Package.ID,
			v[2],
			v[3],
		)
		if err != nil {
			rows.Close()
			if err == pgx.ErrNoRows {
				continue
			}
			return nil, fmt.Errorf("failed to query the manifest index: %v", err)
		}
		for rows.Next() {
			var hash claircore.Digest
			err := rows.Scan(&hash)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning manifest hash into digest: %v", err)
			}
			set[hash.String()] = hash
		}
	}

	n := len(set)
	out := make([]claircore.Digest, 0, n)
	for _, v := range set {
		out = append(out, v)
	}
	log.Debug().Int("count", len(out)).Msg("affected manifests")
	return out, nil
}

// protoRecord is a helper method which resolves a Vulnerability to an IndexRecord with no Package defined.
//
// it is an error for both a distribution and a repo to be missing from the Vulnerability.
func protoRecord(ctx context.Context, pool *pgxpool.Pool, v claircore.Vulnerability) (claircore.IndexRecord, error) {
	const (
		selectDist = `
		SELECT id
		FROM dist
		WHERE arch = $1
		  AND cpe = $2
		  AND did = $3
		  AND name = $4
		  AND pretty_name = $5
		  AND version = $6
		  AND version_code_name = $7
		  AND version_id = $8;
		`
		selectRepo = `
		SELECT id
		FROM repo
		WHERE name = $1
			AND key = $2
			AND uri = $3;
		`
	)
	log := zerolog.Ctx(ctx).
		With().
		Str("component", "internal/indexer/postgres/protoRecord").
		Logger()

	protoRecord := claircore.IndexRecord{}
	// fill dist into prototype index record if exists
	if (v.Dist != nil) && (v.Dist.Name != "") {
		row := pool.QueryRow(ctx,
			selectDist,
			v.Dist.Arch,
			v.Dist.CPE,
			v.Dist.DID,
			v.Dist.Name,
			v.Dist.PrettyName,
			v.Dist.Version,
			v.Dist.VersionCodeName,
			v.Dist.VersionID,
		)
		var id pgtype.Int8
		err := row.Scan(&id)
		if err != nil {
			if err != pgx.ErrNoRows {
				return protoRecord, fmt.Errorf("failed to scan dist: %v", err)
			}
		}
		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Distribution = &claircore.Distribution{
				ID:              id,
				Arch:            v.Dist.Arch,
				CPE:             v.Dist.CPE,
				DID:             v.Dist.DID,
				Name:            v.Dist.Name,
				PrettyName:      v.Dist.PrettyName,
				Version:         v.Dist.Version,
				VersionCodeName: v.Dist.VersionCodeName,
				VersionID:       v.Dist.VersionID,
			}
			log.Debug().Str("id", id).Msg("discovered distribution id")
		}
	}

	// fill repo into prototype index record if exists
	if (v.Repo != nil) && (v.Repo.Name != "") {
		row := pool.QueryRow(ctx, selectRepo,
			v.Repo.Name,
			v.Repo.Key,
			v.Repo.URI,
		)
		var id pgtype.Int8
		err := row.Scan(&id)
		if err != nil {
			if err != pgx.ErrNoRows {
				return protoRecord, fmt.Errorf("failed to scan repo: %v", err)
			}
		}
		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Repository = &claircore.Repository{
				ID:   id,
				Key:  v.Repo.Key,
				Name: v.Repo.Name,
				URI:  v.Repo.URI,
			}
			log.Debug().Str("id", id).Msg("discovered repo id")
		}
	}

	// we need at least a repo or dist to continue.
	if (protoRecord.Distribution == nil) && (protoRecord.Repository == nil) {
		return protoRecord, fmt.Errorf("vuln did not contain a repo or distribution")
	}

	return protoRecord, nil
}
