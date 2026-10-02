package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	"unique"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Queue each distinct SELECT once. Records that render the same SQL are
	// kept on that statement so each scanned row can be offered to all of them.
	batch := &pgx.Batch{}
	bySQL := make(map[string][]*claircore.IndexRecord)
	var queries []string
	for _, record := range records {
		query, err := buildGetQuery(record, &opts)
		if err != nil {
			// if we cannot build a query for an individual record continue to the next
			slog.DebugContext(ctx, "could not build query for record",
				"reason", err,
				"record", record)
			continue
		}
		if _, ok := bySQL[query]; !ok {
			queries = append(queries, query)
			batch.Queue(query)
		}
		bySQL[query] = append(bySQL[query], record)
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
	// intern shares decoded Vulnerability objects by vuln.id across queries
	// in this Get. A row is interned only after Vulnerable accepts it, so
	// later hits skip Scan and rejected rows are not retained.
	intern := map[int64]*claircore.Vulnerability{}
	for _, query := range queries {
		recs := bySQL[query]
		err := func() error {
			rows, err := res.Query()
			if err != nil {
				res.Close()
				return fmt.Errorf("error getting rows: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				id, err := peekInt8(rows)
				if err != nil {
					res.Close()
					return fmt.Errorf("failed to read vulnerability id: %w", err)
				}
				v, ok := intern[id]
				if !ok {
					v = &claircore.Vulnerability{
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
						&v.Invert,
					)
					if err != nil {
						res.Close()
						return fmt.Errorf("failed to scan vulnerability: %w", err)
					}
					v.ID = strconv.FormatInt(id, 10)
				}
				for _, record := range recs {
					if opts.Vulnerable != nil {
						ok, err := opts.Vulnerable(ctx, record, v)
						if err != nil {
							res.Close()
							return err
						}
						if !ok {
							continue
						}
					}
					intern[id] = v
					addVuln(results, vulnSet, record.Package.ID, v)
				}
			}
			if err := rows.Err(); err != nil {
				res.Close()
				return fmt.Errorf("failed to iterate vulnerabilities: %w", err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	if err := res.Close(); err != nil {
		return nil, fmt.Errorf("some weird batch error: %v", err)
	}

	getVulnerabilitiesCounter.WithLabelValues("query_batch").Add(1)
	getVulnerabilitiesDuration.WithLabelValues("query_batch").Observe(time.Since(start).Seconds())

	if err := populateAliases(ctx, tx, results); err != nil {
		return nil, fmt.Errorf("populating aliases: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}

func addVuln(results map[string][]*claircore.Vulnerability, vulnSet map[string]map[string]struct{}, rid string, v *claircore.Vulnerability) {
	if _, ok := vulnSet[rid]; !ok {
		vulnSet[rid] = make(map[string]struct{})
	}
	if _, ok := vulnSet[rid][v.ID]; ok {
		return
	}
	vulnSet[rid][v.ID] = struct{}{}
	results[rid] = append(results[rid], v)
}

// peekInt8 returns column 0 as int64 without decoding the rest of the row.
// Scan can only be called once per row, so intern hits must skip via RawValues.
func peekInt8(rows pgx.Rows) (int64, error) {
	raw := rows.RawValues()
	if len(raw) == 0 || raw[0] == nil {
		return 0, fmt.Errorf("missing id")
	}
	format := int16(pgx.TextFormatCode)
	if fds := rows.FieldDescriptions(); len(fds) > 0 {
		format = fds[0].Format
	}
	return decodeInt8(raw[0], format)
}

func decodeInt8(src []byte, format int16) (int64, error) {
	if format == pgx.BinaryFormatCode {
		if len(src) != 8 {
			return 0, fmt.Errorf("binary int8: %d bytes", len(src))
		}
		return int64(binary.BigEndian.Uint64(src)), nil
	}
	return strconv.ParseInt(string(src), 10, 64)
}

// populateAliases fetches aliases and self references for all vulnerabilities
// in the results map and populates the Aliases and Self fields.
func populateAliases(ctx context.Context, tx pgx.Tx, results map[string][]*claircore.Vulnerability) error {
	vulnByID := make(map[string]*claircore.Vulnerability)
	for _, vulns := range results {
		for _, v := range vulns {
			vulnByID[v.ID] = v
		}
	}
	if len(vulnByID) == 0 {
		return nil
	}

	ids := make([]int64, 0, len(vulnByID))
	for id := range vulnByID {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, n)
	}

	const aliasQuery = `
		SELECT va.vulnerability, ns.namespace, a.name
		FROM vulnerability_alias va
		JOIN alias a ON va.alias = a.id
		JOIN alias_namespace ns ON a.namespace = ns.id
		WHERE va.vulnerability = ANY($1::bigint[])
	`
	aliasRows, err := tx.Query(ctx, aliasQuery, ids)
	if err != nil {
		return fmt.Errorf("querying aliases: %w", err)
	}
	defer aliasRows.Close()

	for aliasRows.Next() {
		var vulnID int64
		var namespace, name string
		if err := aliasRows.Scan(&vulnID, &namespace, &name); err != nil {
			return fmt.Errorf("scanning alias row: %w", err)
		}
		v := vulnByID[strconv.FormatInt(vulnID, 10)]
		if v == nil {
			continue
		}
		v.Aliases = append(v.Aliases, claircore.Alias{
			Space: unique.Make(namespace),
			Name:  name,
		})
	}
	if err := aliasRows.Err(); err != nil {
		return fmt.Errorf("iterating alias rows: %w", err)
	}

	const selfQuery = `
		SELECT vs.vulnerability, ns.namespace, a.name
		FROM vulnerability_self vs
		JOIN alias a ON vs.self = a.id
		JOIN alias_namespace ns ON a.namespace = ns.id
		WHERE vs.vulnerability = ANY($1::bigint[])
	`
	selfRows, err := tx.Query(ctx, selfQuery, ids)
	if err != nil {
		return fmt.Errorf("querying self aliases: %w", err)
	}
	defer selfRows.Close()

	for selfRows.Next() {
		var vulnID int64
		var namespace, name string
		if err := selfRows.Scan(&vulnID, &namespace, &name); err != nil {
			return fmt.Errorf("scanning self row: %w", err)
		}
		v := vulnByID[strconv.FormatInt(vulnID, 10)]
		if v == nil {
			continue
		}
		v.Self = claircore.Alias{
			Space: unique.Make(namespace),
			Name:  name,
		}
	}
	if err := selfRows.Err(); err != nil {
		return fmt.Errorf("iterating self rows: %w", err)
	}

	return nil
}
