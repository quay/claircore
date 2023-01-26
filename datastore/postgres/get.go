package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v4"
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

// Get implements vulnstore.Vulnerability.
func (s *MatcherStore) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	const op = `datastore/postgres/MatcherStore.Get`
	ctx = zlog.ContextWithValues(ctx, "component", op)
	results := make(map[string][]*claircore.Vulnerability)
	err := s.pool.BeginTxFunc(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) (err error) {
		defer getVulnerabilitiesCounter.WithLabelValues("query_batch").Inc()
		defer prometheus.NewTimer(getVulnerabilitiesDuration.WithLabelValues("query_batch")).ObserveDuration()
		var batch pgx.Batch
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
			// queue the select query
			batch.Queue(query)
		}
		res := tx.SendBatch(ctx, &batch)
		defer func() {
			if err := res.Close(); err != nil && !errors.Is(err, context.Canceled) {
				zlog.Info(ctx).Err(err).Msg("error closing batch")
			}
		}()

		// gather all the returned vulns for each queued select statement
		vulnSet := make(map[string]map[string]struct{})
		for _, record := range records {
			var rows pgx.Rows
			rows, err = res.Query()
			if err != nil {
				return &claircore.Error{
					Op:      op,
					Kind:    claircore.ErrInternal,
					Message: "query failed",
					Inner:   err,
				}
			}

			// unpack all returned rows into claircore.Vulnerability structs
			var id int64
			for rows.Next() {
				// fully allocate vuln struct
				v := &claircore.Vulnerability{
					Package: &claircore.Package{},
					Dist:    &claircore.Distribution{},
					Repo:    &claircore.Repository{},
				}

				err = rows.Scan(
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
				if err != nil {
					return &claircore.Error{
						Op:      op,
						Kind:    claircore.ErrInternal,
						Message: "failed to deserialize vulnerability",
						Inner:   err,
					}
				}
				v.ID = strconv.FormatInt(id, 10)
				rid := record.Package.ID
				if _, ok := vulnSet[rid]; !ok {
					vulnSet[rid] = make(map[string]struct{})
				}
				if _, ok := vulnSet[rid][v.ID]; !ok {
					vulnSet[rid][v.ID] = struct{}{}
					results[rid] = append(results[rid], v)
				}
			}
		}
		return nil
	})
	if err != nil {
		var domErr *claircore.Error
		if !errors.As(err, &domErr) {
			domErr = &claircore.Error{
				Op:      op,
				Inner:   err,
				Kind:    claircore.ErrInternal,
				Message: "other database error",
			}
		}
		return nil, domErr
	}
	return results, nil
}
