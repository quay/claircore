package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unique"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	zeroRepo claircore.Repository
	zeroDist claircore.Distribution
)

var (
	updateVulnerabilitiesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updatevulnerabilities_total",
			Help:      "Total number of database queries issued in the UpdateVulnerabilities method.",
		},
		[]string{"query", "is_delta"},
	)
	updateVulnerabilitiesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updatevulnerabilities_duration_seconds",
			Help:      "The duration of all queries issued in the UpdateVulnerabilities method",
		},
		[]string{"query", "is_delta"},
	)
)

// UpdateVulnerabilitiesIter implements vulnstore.Updater.
func (s *MatcherStore) UpdateVulnerabilitiesIter(ctx context.Context, updater string, fp driver.Fingerprint, it datastore.VulnerabilityIter) (uuid.UUID, error) {
	return s.updateVulnerabilities(ctx, updater, fp, it, nil)
}

// UpdateVulnerabilities implements vulnstore.Updater.
//
// It creates a new UpdateOperation for this update call, inserts the
// provided vulnerabilities and computes a diff comprising the removed
// and added vulnerabilities for this UpdateOperation.
func (s *MatcherStore) UpdateVulnerabilities(ctx context.Context, updater string, fp driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	iterVulns := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vulns {
			if !yield(vulns[i], nil) {
				break
			}
		}
	}
	return s.updateVulnerabilities(ctx, updater, fp, iterVulns, nil)
}

// DeltaUpdateVulnerabilities implements vulnstore.Updater.
//
// It is similar to UpdateVulnerabilities but support processing of
// partial data as opposed to needing an entire vulnerability database
// Order of operations:
//   - Create a new UpdateOperation
//   - Query existing vulnerabilities for the updater
//   - Discount and vulnerabilities with newer updates and deleted vulnerabilities
//   - Update the associated updateOperation for the remaining existing vulnerabilities
//   - Insert the new vulnerabilities
//   - Associate new vulnerabilities with new updateOperation
func (s *MatcherStore) DeltaUpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability, deletedVulns []string) (uuid.UUID, error) {
	iterVulns := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vulns {
			if !yield(vulns[i], nil) {
				break
			}
		}
	}
	delVulns := func(yield func(string, error) bool) {
		for _, s := range deletedVulns {
			if !yield(s, nil) {
				break
			}
		}
	}
	return s.updateVulnerabilities(ctx, updater, fingerprint, iterVulns, delVulns)
}

func (s *MatcherStore) updateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulnIter datastore.VulnerabilityIter, delIter datastore.Iter[string]) (uuid.UUID, error) {
	const (
		// Create makes a new update operation and returns the reference and ID.
		create = `INSERT INTO update_operation (updater, fingerprint, kind) VALUES ($1, $2, 'vulnerability') RETURNING id, ref;`
		// Select existing vulnerabilities that are associated with the latest_update_operation.
		selectExisting = `
		SELECT
			"name",
			"vuln"."id"
		FROM
			"vuln"
			INNER JOIN "uo_vuln" ON ("vuln"."id" = "uo_vuln"."vuln")
			INNER JOIN "latest_update_operations" ON (
			"latest_update_operations"."id" = "uo_vuln"."uo"
			)
		WHERE
			(
			"latest_update_operations"."kind" = 'vulnerability'
			)
		AND
			(
			"vuln"."updater" = $1
			)`
		// assocExisting associates existing vulnerabilities with new update operations
		assocExisting = `INSERT INTO uo_vuln (uo, vuln) VALUES ($1, $2) ON CONFLICT DO NOTHING;`
		// Insert attempts to create a new vulnerability. It fails silently.
		insert = `
		INSERT INTO vuln (
			hash_kind, hash,
			name, updater, description, issued, links, severity, normalized_severity,
			package_name, package_version, package_module, package_arch, package_kind,
			dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
			repo_name, repo_key, repo_uri,
			fixed_in_version, arch_operation, version_kind, vulnerable_range,
			not_vulnerable
		) VALUES (
		  $1, $2,
		  $3, $4, $5, $6, $7, $8, $9,
		  $10, $11, $12, $13, $14,
		  $15, $16, $17, $18, $19, $20, $21, $22,
		  $23, $24, $25,
		  $26, $27, $28, COALESCE($29, VersionRange('{}', '{}', '()')),
		  $30
		)
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		// Assoc associates an update operation and a vulnerability. It fails
		// silently.
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
		refreshView = `REFRESH MATERIALIZED VIEW CONCURRENTLY latest_update_operations;`
		// bulkLinkAliases links all vulnerability→alias rows in one statement by
		// joining the flattened (hash_kind, hash, alias_space, alias_name) arrays
		// against the already-populated vuln and alias tables.
		bulkLinkAliases = `
		INSERT INTO vulnerability_alias (vulnerability, alias)
		SELECT v.id, a.id
		FROM
			unnest($1::TEXT[], $2::BYTEA[], $3::TEXT[], $4::TEXT[])
				AS input(hash_kind, hash, alias_space, alias_name)
		JOIN
			vuln v ON v.hash_kind = input.hash_kind AND v.hash = input.hash
		JOIN
			alias_namespace ns ON ns.namespace = input.alias_space
		JOIN
			alias a ON a.name = input.alias_name AND a.namespace = ns.id
		ON CONFLICT DO NOTHING`
		// bulkLinkSelf links all vulnerability→self rows in one statement.
		bulkLinkSelf = `
		INSERT INTO vulnerability_self (vulnerability, self)
		SELECT v.id, a.id
		FROM
			unnest($1::TEXT[], $2::BYTEA[], $3::TEXT[], $4::TEXT[])
				AS input(hash_kind, hash, self_space, self_name)
		JOIN
			vuln v ON v.hash_kind = input.hash_kind AND v.hash = input.hash
		JOIN
			alias_namespace ns ON ns.namespace = input.self_space
		JOIN
			alias a ON a.name = input.self_name AND a.namespace = ns.id
		ON CONFLICT DO NOTHING`
		// insertAliasNamespaces creates all needed namespace rows outside any
		// transaction so concurrent updaters do not deadlock.
		insertAliasNamespaces = `INSERT INTO alias_namespace (namespace) VALUES (unnest($1::TEXT[])) ON CONFLICT DO NOTHING;`
		// insertAliases creates all needed alias rows outside any transaction.
		insertAliases = `INSERT INTO alias (namespace, name)
	SELECT ns.id, input.name
	FROM
		(SELECT unnest($1::TEXT[]) AS space, unnest($2::TEXT[]) AS name) AS input
	JOIN
		alias_namespace AS ns ON input.space = ns.namespace
ON CONFLICT DO NOTHING;`
	)

	var uoID uint64
	var ref uuid.UUID

	start := time.Now()

	// The isolation level must be pinned to "read committed" (rather than
	// inheriting default_transaction_isolation) because linkFlush's
	// INSERT..SELECT statements need to see alias rows committed outside this
	// transaction after it began.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, create, updater, string(fingerprint)).Scan(&uoID, &ref); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}

	delta := delIter != nil
	updateVulnerabilitiesCounter.WithLabelValues("create", strconv.FormatBool(delta)).Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("create", strconv.FormatBool(delta)).Observe(time.Since(start).Seconds())

	log := slog.With("ref", ref)
	log.DebugContext(ctx, "update_operation created")

	if delta {
		log = log.With("mode", "delta")
		// Get existing vulns
		// The reason this still works even though the new update_operation
		// is already created is because the latest_update_operation view isn't updated until
		// the end of this function.
		start = time.Now()
		rows, err := s.pool.Query(ctx, selectExisting, updater)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to get existing vulns: %w", err)
		}
		defer rows.Close()
		updateVulnerabilitiesCounter.WithLabelValues("selectExisting", strconv.FormatBool(delta)).Add(1)
		updateVulnerabilitiesDuration.WithLabelValues("selectExisting", strconv.FormatBool(delta)).Observe(time.Since(start).Seconds())

		oldVulns := make(map[string][]string)
		for rows.Next() {
			var tmpID int64
			var ID, name string
			err := rows.Scan(
				&name,
				&tmpID,
			)

			ID = strconv.FormatInt(tmpID, 10)
			if err != nil {
				return uuid.Nil, fmt.Errorf("failed to scan vulnerability: %w", err)
			}
			oldVulns[name] = append(oldVulns[name], ID)
		}
		if err := rows.Err(); err != nil {
			return uuid.Nil, fmt.Errorf("error reading existing vulnerabilities: %w", err)
		}

		if len(oldVulns) > 0 {
			vulnIter(func(v *claircore.Vulnerability, _ error) bool {
				// If we have an existing vuln in the new batch
				// delete it from the oldVulns map so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, v.Name)
				return true
			})
			delIter(func(delName string, _ error) bool {
				// If we have an existing vuln that has been signaled
				// as deleted by the updater then delete it so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, delName)
				return true
			})
		}
		start = time.Now()
		// Associate already existing vulnerabilities with new update_operation.
		for _, vs := range oldVulns {
			for _, vID := range vs {
				_, err := tx.Exec(ctx, assocExisting, uoID, vID)
				if err != nil {
					return uuid.Nil, fmt.Errorf("could not update old vulnerability with new UO: %w", err)
				}
			}
		}
		updateVulnerabilitiesCounter.WithLabelValues("assocExisting", strconv.FormatBool(delta)).Add(float64(len(oldVulns)))
		updateVulnerabilitiesDuration.WithLabelValues("assocExisting", strconv.FormatBool(delta)).Observe(time.Since(start).Seconds())

	}

	// batch insert vulnerabilities
	skipCt := 0
	vulnCt := 0
	start = time.Now()
	var batch pgx.Batch
	flush := func() (err error) {
		err = tx.SendBatch(ctx, &batch).Close()
		resetSlices(&batch.QueuedQueries)
		return err
	}

	// Columns for the bulk alias-linking statements, flushed alongside the
	// vulnerability insert batch to bound memory usage. Each entry in va
	// corresponds to one (vuln, alias) pair; each entry in vs to one
	// (vuln, self) pair.
	var va, vs linkCols
	// Namespaces and aliases not yet inserted, i.e., first seen in the
	// current chunk.
	var (
		newSpaces                     []string
		newAliasSpaces, newAliasNames []string
	)
	seenSpace := make(map[unique.Handle[string]]struct{})
	seenAlias := make(map[claircore.Alias]struct{})

	// linkDur accumulates time spent in linkFlush so the link_aliases metric
	// covers the per-chunk flushes and insert_batch excludes them.
	var linkDur time.Duration

	// linkFlush inserts the alias namespaces and aliases first seen in the
	// current chunk (outside the transaction to avoid deadlocks between
	// concurrent updaters), then links the current chunk's (vuln, alias) and
	// (vuln, self) pairs inside the transaction. The vulnerability rows of
	// the chunk must have been flushed to the transaction already.
	linkFlush := func() error {
		defer func(t time.Time) { linkDur += time.Since(t) }(time.Now())
		if len(newSpaces) > 0 {
			if _, err := s.pool.Exec(ctx, insertAliasNamespaces, newSpaces); err != nil {
				return fmt.Errorf("failed to insert alias namespaces: %w", err)
			}
		}
		if len(newAliasNames) > 0 {
			if _, err := s.pool.Exec(ctx, insertAliases, newAliasSpaces, newAliasNames); err != nil {
				return fmt.Errorf("failed to insert aliases: %w", err)
			}
		}
		// Enforce using uncached plans because with more than a few chunks,
		// the generic plan (built for unnest's default row estimate) is
		// chosen and is far slower for the actual array sizes.
		if len(va.hashKinds) > 0 {
			if _, err := tx.Exec(ctx, bulkLinkAliases, pgx.QueryExecModeExec, va.hashKinds, va.hashes, va.spaces, va.names); err != nil {
				return fmt.Errorf("failed to bulk link vulnerability aliases: %w", err)
			}
		}
		if len(vs.hashKinds) > 0 {
			if _, err := tx.Exec(ctx, bulkLinkSelf, pgx.QueryExecModeExec, vs.hashKinds, vs.hashes, vs.spaces, vs.names); err != nil {
				return fmt.Errorf("failed to bulk link vulnerability self aliases: %w", err)
			}
		}
		clear(seenSpace)
		clear(seenAlias)
		resetSlices(&newSpaces, &newAliasSpaces, &newAliasNames)
		va.reset()
		vs.reset()
		return nil
	}

	vulnIter(func(vuln *claircore.Vulnerability, iterErr error) bool {
		if iterErr != nil {
			err = iterErr
			return false
		}
		vulnCt++
		if skipVulnerability(vuln) {
			skipCt++
			return true
		}

		pkg := vuln.Package
		dist := vuln.Dist
		repo := vuln.Repo
		if dist == nil {
			dist = &zeroDist
		}
		if repo == nil {
			repo = &zeroRepo
		}
		hashKind, hash := md5Vuln(vuln)
		vKind, _, _ := rangefmt(vuln.Range)

		batch.Queue(
			insert,
			hashKind, hash,
			vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, vKind, vuln.Range,
			vuln.Invert,
		)
		batch.Queue(assoc, hashKind, hash, uoID)

		// Accumulate alias links for the bulk statements below.
		stage := func(a claircore.Alias) {
			if _, ok := seenSpace[a.Space]; !ok {
				seenSpace[a.Space] = struct{}{}
				newSpaces = append(newSpaces, a.Space.Value())
			}
			if _, ok := seenAlias[a]; !ok {
				seenAlias[a] = struct{}{}
				newAliasSpaces = append(newAliasSpaces, a.Space.Value())
				newAliasNames = append(newAliasNames, a.Name)
			}
		}
		for _, a := range vuln.Aliases {
			if !a.Valid() {
				continue
			}
			stage(a)
			va.add(hashKind, hash, a)
		}
		if vuln.Self.Valid() {
			stage(vuln.Self)
			vs.add(hashKind, hash, vuln.Self)
		}

		if ct := batch.Len(); ct < 1000 {
			return true
		}
		if err = flush(); err != nil {
			err = fmt.Errorf("failed batching: %w", err)
			return false
		}
		if err = linkFlush(); err != nil {
			return false
		}
		return true
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("iterating on vulnerabilities: %w", err)
	}
	if err := flush(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish batch vulnerability insert: %w", err)
	}

	updateVulnerabilitiesCounter.WithLabelValues("insert_batch", strconv.FormatBool(delta)).Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("insert_batch", strconv.FormatBool(delta)).Observe((time.Since(start) - linkDur).Seconds())

	// Link any remainder not covered by the periodic flushes above.
	if err := linkFlush(); err != nil {
		return uuid.Nil, err
	}
	updateVulnerabilitiesCounter.WithLabelValues("link_aliases", strconv.FormatBool(delta)).Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("link_aliases", strconv.FormatBool(delta)).Observe(linkDur.Seconds())

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	if _, err = s.pool.Exec(ctx, refreshView); err != nil {
		return uuid.Nil, fmt.Errorf("could not refresh latest_update_operations: %w", err)
	}

	log.DebugContext(ctx, "update_operation committed",
		"skipped", skipCt,
		"inserted", vulnCt-skipCt)
	return ref, nil
}

// LinkCols is the set of flattened parallel arrays passed to one of the bulk
// alias-linking statements: one entry per (vuln, alias) pair. The hash is
// repeated once per alias so the unnest join can match each row to its vuln.
type linkCols struct {
	hashKinds []string
	hashes    [][]byte
	spaces    []string
	names     []string
}

func (l *linkCols) add(hashKind string, hash []byte, a claircore.Alias) {
	l.hashKinds = append(l.hashKinds, hashKind)
	l.hashes = append(l.hashes, hash)
	l.spaces = append(l.spaces, a.Space.Value())
	l.names = append(l.names, a.Name)
}

func (l *linkCols) reset() {
	resetSlices(&l.hashKinds, &l.spaces, &l.names)
	resetSlices(&l.hashes)
}

// ResetSlices truncates the passed slices, keeping their backing arrays for
// reuse but clearing the elements so anything they reference can be
// collected.
func resetSlices[T any](slices ...*[]T) {
	for _, s := range slices {
		clear(*s)
		*s = (*s)[:0]
	}
}

// SkipVulnerability reports if the provided [claircore.Vulnerability] should
// not be uploaded to the database.
func skipVulnerability(v *claircore.Vulnerability) bool {
	// TODO(hank) Check the vulnerability aliases. This requires *all* the
	// updaters being touched.
	return v.Package == nil || v.Package.Name == ""
}

func rangefmt(r *claircore.Range) (kind *string, lower, upper string) {
	lower, upper = "{}", "{}"
	if r == nil || r.Lower.Kind != r.Upper.Kind {
		return kind, lower, upper
	}

	kind = &r.Lower.Kind // Just tested the both kinds are the same.
	v := &r.Lower
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	lower = buf.String()
	buf.Reset()
	v = &r.Upper
	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	upper = buf.String()

	return kind, lower, upper
}
