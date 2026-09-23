package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"
	"unique"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/cpe"
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

// getQuery is one unique SELECT and the package IDs that should receive its rows.
type getQuery struct {
	sql    string
	pkgIDs []string
}

// Get implements vulnstore.Vulnerability.
func (s *MatcherStore) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	batch := &pgx.Batch{}
	queries := planGetQueries(ctx, records, &opts)
	for _, q := range queries {
		batch.Queue(q.sql)
	}

	start := time.Now()
	res := tx.SendBatch(ctx, batch)
	// The batch must be fully consumed before the transaction can resolve.

	intern := vulnIntern{}
	results := make(map[string][]*claircore.Vulnerability)
	seen := make(map[string]map[string]struct{})
	vulnAdd := func(pkgID string, v *claircore.Vulnerability) {
		if seen[pkgID] == nil {
			seen[pkgID] = make(map[string]struct{})
		}
		if _, ok := seen[pkgID][v.ID]; ok {
			return
		}
		seen[pkgID][v.ID] = struct{}{}
		results[pkgID] = append(results[pkgID], v)
	}

	for _, q := range queries {
		err := func() error {
			rows, err := res.Query()
			if err != nil {
				res.Close()
				return fmt.Errorf("error getting rows: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				v, err := intern.Scan(rows)
				if err != nil {
					res.Close()
					return err
				}
				for _, pkgID := range q.pkgIDs {
					vulnAdd(pkgID, v)
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

	if err := populateAliases(ctx, tx, intern); err != nil {
		return nil, fmt.Errorf("populating aliases: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}

// planGetQueries builds one SELECT per distinct package lookup.
//
// Records that differ only by repository CPE share a statement: the package,
// module, and repo key predicates stay as they are, and each record CPE is
// OR'd into the CPE comparison. Records with no CPE keep the unfiltered
// statement so they are not narrowed by a sibling's CPE.
func planGetQueries(ctx context.Context, records []*claircore.IndexRecord, opts *datastore.GetOpts) []*getQuery {
	baseOpts := *opts
	filterCPE := slices.Contains(opts.Matchers, driver.CPECompare)
	if filterCPE {
		baseOpts.Matchers = slices.DeleteFunc(slices.Clone(opts.Matchers), func(m driver.MatchConstraint) bool {
			return m == driver.CPECompare
		})
	}

	// noCPE keeps a record with an empty CPE out of the bucket whose statement
	// is narrowed by the CPEs collected from its siblings.
	type queryKey struct {
		sql   string
		noCPE bool
	}
	type bucket struct {
		record  *claircore.IndexRecord
		base    string
		cpes    []cpe.WFN
		seenFS  map[string]struct{}
		pkgIDs  []string
		seenPkg map[string]struct{}
	}
	var order []*bucket
	byKey := map[queryKey]*bucket{}
	add := func(key queryKey, record *claircore.IndexRecord, base string, w *cpe.WFN) {
		b, ok := byKey[key]
		if !ok {
			b = &bucket{
				record:  record,
				base:    base,
				seenFS:  map[string]struct{}{},
				seenPkg: map[string]struct{}{},
			}
			byKey[key] = b
			order = append(order, b)
		}
		if w != nil {
			fs := w.String()
			if _, ok := b.seenFS[fs]; !ok && fs != "" {
				b.seenFS[fs] = struct{}{}
				b.cpes = append(b.cpes, *w)
			}
		}
		id := record.Package.ID
		if _, ok := b.seenPkg[id]; ok {
			return
		}
		b.seenPkg[id] = struct{}{}
		b.pkgIDs = append(b.pkgIDs, id)
	}

	for _, record := range records {
		base, err := buildGetQuery(record, &baseOpts)
		if err != nil {
			slog.DebugContext(ctx, "could not build query for record",
				"reason", err,
				"record", record)
			continue
		}
		var w *cpe.WFN
		if filterCPE && record.Repository != nil && record.Repository.CPE.String() != "" {
			w = &record.Repository.CPE
		}
		add(queryKey{sql: base, noCPE: w == nil}, record, base, w)
	}

	queries := make([]*getQuery, 0, len(order))
	for _, b := range order {
		sql := b.base
		if len(b.cpes) > 0 {
			var err error
			sql, err = buildGetQueryCPEs(b.record, opts, b.cpes)
			if err != nil {
				slog.DebugContext(ctx, "could not build query for record",
					"reason", err,
					"record", b.record)
				continue
			}
		}
		queries = append(queries, &getQuery{sql: sql, pkgIDs: b.pkgIDs})
	}
	return queries
}

// vulnIntern stores one Vulnerability per database id for a single Get call.
type vulnIntern map[int64]*claircore.Vulnerability

// Scan returns the row's Vulnerability, sharing one object per vuln.id so
// overlapping source-name rows are not fully decoded again.
func (in vulnIntern) Scan(rows pgx.Rows) (*claircore.Vulnerability, error) {
	id, err := peekInt8(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulnerability id: %w", err)
	}
	if v, ok := in[id]; ok {
		return v, nil
	}
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
		&v.Invert,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
	}
	v.ID = strconv.FormatInt(id, 10)
	in[id] = v
	return v, nil
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

// populateAliases fetches aliases and self references for the vulnerabilities
// in vulns and populates the Aliases and Self fields. Those pointers are the
// same objects returned in the Get results.
func populateAliases(ctx context.Context, tx pgx.Tx, vulns vulnIntern) error {
	if len(vulns) == 0 {
		return nil
	}

	ids := make([]int64, 0, len(vulns))
	for id := range vulns {
		ids = append(ids, id)
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
		v := vulns[vulnID]
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
		v := vulns[vulnID]
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
