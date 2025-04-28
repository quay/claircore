package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
)

var (
	getVulnerabilitiesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getvulnerabilities_total",
			Help:      "Total number of database queries issued in the get method.",
		},
		[]string{"query"},
	)
	getVulnerabilitiesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "getvulnerabilities_duration_seconds",
			Help:      "The duration of all queries issued in the get method",
		},
		[]string{"query"},
	)
)

type recordQuery struct {
	record *claircore.IndexRecord
	query  string
}

// Get implements vulnstore.Vulnerability.
func (s *MatcherStore) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/Get")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// start a batch
	batch := &pgx.Batch{}
	resCache := map[string][]*claircore.Vulnerability{}
	rqs := []*recordQuery{}
	for _, record := range records {
		query, err := buildGetQuery(record, &opts)
		if err != nil {
			// if we cannot build a query for an individual record continue to the next
			zlog.Debug(ctx).
				Err(err).
				Str("record", fmt.Sprintf("%+v", record)).
				Msg("could not build query for record")
			continue
		}
		rqs = append(rqs, &recordQuery{query: query, record: record})
		if _, ok := resCache[query]; ok {
			continue
		}
		// queue the select query
		batch.Queue(query)
		resCache[query] = nil
	}
	// send the batch
	start := time.Now()
	res := tx.SendBatch(ctx, batch)
	// Can't just defer the close, because the batch must be fully handled
	// before resolving the transaction. Maybe we can move this result handling
	// into its own function to be able to just defer it.

	// gather all the returned vulns for each queued select statement
	results := make(map[string][]*claircore.Vulnerability)
	vulnSet := make(map[string]map[string]struct{})
	for _, rq := range rqs {
		rid := rq.record.Package.ID
		vulns, ok := resCache[rq.query]
		if !ok {
			return nil, fmt.Errorf("unexpected vulnerability query: %s", rq.query)
		}
		if vulns != nil { // We already have results we don't need to go back to the DB.
			if _, ok := vulnSet[rid]; !ok {
				vulnSet[rid] = make(map[string]struct{})
			}
			for _, v := range vulns {
				if _, ok := vulnSet[rid][v.ID]; !ok {
					vulnSet[rid][v.ID] = struct{}{}
					results[rid] = append(results[rid], v)
				}
			}
			continue
		}
		results[rid] = []*claircore.Vulnerability{}
		err := func() error {
			rows, err := res.Query()
			if err != nil {
				res.Close()
				return fmt.Errorf("error getting rows: %w", err)
			}
			defer rows.Close()
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
					&v.Issued,
					&v.Links,
					&v.Severity,
					&v.NormalizedSeverity,
					&v.Package.Name,
					&v.Package.Version,
					&v.Package.Module,
					&v.Package.Arch,
					&v.Package.Kind,
					&v.Dist.DID,
					&v.Dist.Name,
					&v.Dist.Version,
					&v.Dist.VersionCodeName,
					&v.Dist.VersionID,
					&v.Dist.Arch,
					&v.Dist.CPE,
					&v.Dist.PrettyName,
					&v.ArchOperation,
					&v.Repo.Name,
					&v.Repo.Key,
					&v.Repo.URI,
					&v.FixedInVersion,
					&v.Updater,
				)
				v.ID = strconv.FormatInt(id, 10)
				if err != nil {
					res.Close()
					return fmt.Errorf("failed to scan vulnerability: %w", err)
				}

				if _, ok := vulnSet[rid]; !ok {
					vulnSet[rid] = make(map[string]struct{})
				}
				if _, ok := vulnSet[rid][v.ID]; !ok {
					vulnSet[rid][v.ID] = struct{}{}
					results[rid] = append(results[rid], v)
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
		resCache[rq.query] = results[rid]
	}
	if err := res.Close(); err != nil {
		return nil, fmt.Errorf("some weird batch error: %v", err)
	}

	getVulnerabilitiesCounter.WithLabelValues("query_batch").Add(1)
	getVulnerabilitiesDuration.WithLabelValues("query_batch").Observe(time.Since(start).Seconds())

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}
