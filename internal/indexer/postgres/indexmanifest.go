package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/microbatch"
)

func indexManifest(ctx context.Context, pool *pgxpool.Pool, ir *claircore.IndexReport) error {
	const (
		query = `
		INSERT INTO manifest_index(package_id, dist_id, repo_id, manifest_hash)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING;
		`
	)
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/postgres/indexManifest").
		Logger()

	if ir.Hash.String() == "" {
		return fmt.Errorf("received empty hash. cannot associate contents with a manifest hash")
	}
	hash := ir.Hash.String()

	records := ir.IndexRecords()
	if len(records) == 0 {
		log.Warn().Msg("manifest being indexed has 0 scan records")
		return nil
	}

	// obtain a transaction scoped batch
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: indexManifest failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	queryStmt, err := tx.Prepare(ctx, "queryStmt", query)
	if err != nil {
		return fmt.Errorf("failed to create statement: %v", err)
	}

	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, record := range records {
		// ignore nil packages
		if record.Package == nil {
			continue
		}

		v, err := toValues(*record)
		if err != nil {
			return fmt.Errorf("received a record with an invalid id: %v", err)
		}

		// if source package exists create record
		if v[0] != nil {
			err = mBatcher.Queue(
				ctx,
				queryStmt.SQL,
				v[0],
				v[2],
				v[3],
				hash,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for source package record %v: %v", record, err)
			}
		}

		err = mBatcher.Queue(
			ctx,
			queryStmt.SQL,
			v[1],
			v[2],
			v[3],
			hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package record %v: %v", record, err)
		}

	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit tx: %v", err)
	}
	return nil
}

// toValues is a helper method which checks for
// nil pointers inside an IndexRecord before
// returning an associated pointer to the artifact
// in question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) ([4]*uint64, error) {
	res := [4]*uint64{}

	if r.Package.Source != nil {
		id, err := strconv.ParseUint(r.Package.Source.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("source package id %v: %v", r.Package.ID, err)
		}
		res[0] = &id
	}

	if r.Package != nil {
		id, err := strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %v", r.Package.ID, err)
		}
		res[1] = &id

	}

	if r.Distribution != nil {
		id, err := strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %v", r.Distribution.ID, err)
		}
		res[2] = &id
	}

	if r.Repository != nil {
		id, err := strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			// return res, fmt.Errorf("repository id %v: %v", r.Package.ID, err)
			return res, nil
		}
		res[3] = &id
	}

	return res, nil
}
