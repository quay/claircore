package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

func get(ctx context.Context, pool *pgxpool.Pool, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/get").
		Logger()
	ctx = log.WithContext(ctx)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// start a batch
	batch := &pgx.Batch{}
	for _, record := range records {
		query, err := buildGetQuery(record, opts.Matchers)
		if err != nil {
			// if we cannot build a query for an individual record continue to the next
			log.Debug().Str("record", fmt.Sprintf("%+v", record)).Msg("could not build query for record")
			continue
		}
		// queue the select query
		batch.Queue(query)
	}
	// send the batch
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res := tx.SendBatch(tctx, batch)
	// Can't just defer the close, because the batch must be fully handled
	// before resolving the transaction. Maybe we can move this result handling
	// into its own function to be able to just defer it.

	// gather all the returned vulns for each queued select statement
	results := make(map[string][]*claircore.Vulnerability)
	for _, record := range records {
		rows, err := res.Query()
		if err != nil {
			res.Close()
			return nil, err
		}

		// unpack all returned rows into claircore.Vulnerability structs
		for rows.Next() {
			// fully allocate vuln struct
			v := &claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}

			var id int64
			err := rows.Scan(
				&id,
				&v.Name,
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
				&v.Repo.Name,
				&v.Repo.Key,
				&v.Repo.URI,
				&v.Dist.PrettyName,
				&v.FixedInVersion,
			)
			v.ID = strconv.FormatInt(id, 10)
			if err != nil {
				res.Close()
				return nil, fmt.Errorf("failed to scan vulnerability: %v", err)
			}

			// add vulernability to result. handle if array does not exist
			if _, ok := results[record.Package.ID]; !ok {
				vvulns := []*claircore.Vulnerability{v}
				results[record.Package.ID] = vvulns
			} else {
				results[record.Package.ID] = append(results[record.Package.ID], v)
			}
		}
	}
	if err := res.Close(); err != nil {
		return nil, fmt.Errorf("some weird batch error: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}
