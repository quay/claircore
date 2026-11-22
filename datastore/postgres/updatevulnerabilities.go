package postgres

import (
	"context"
	_ "embed" // for queries
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

var (
	//go:embed query/updatevulnerabilities_associate_update_operation_vuln.sql
	updateVulnerabilitiesAssociateUpdateOperationVuln string
	//go:embed query/updatevulnerabilities_select_vuln_by_hash.sql
	updateVulnerabilitiesSelectVulnByHash string
	//go:embed query/updatevulnerabilities_insert_alias_namespace.sql
	updateVulnerabilitiesInsertAliasNamespace string
	//go:embed query/updatevulnerabilities_insert_alias.sql
	updateVulnerabilitiesInsertAlias string
	//go:embed query/updatevulnerabilities_select_alias.sql
	updateVulnerabilitiesSelectAlias string
	//go:embed query/updatevulnerabilities_insert_vulnerability_alias.sql
	updateVulnerabilitiesInsertVulnerabilityAlias string
	//go:embed query/updatevulnerabilities_insert_vulnerability_self.sql
	updateVulnerabilitiesInsertVulnerabilitySelf string
	// Insert attempts to create a new vulnerability. It fails silently.
	//
	//go:embed query/updatevulnerabilities_insert_vuln.sql
	updateVulnerabilitiesInsertVuln string
)

// Staging column lists and SQL used by the COPY-based bulk insert path in
// [MatcherStore.updateVulnerabilities]. The tmp_vuln column order MUST match the
// order values are appended in the insert loop and the SELECT in
// stagingInsertVuln.
var (
	tmpVulnColumns = []string{
		"hash_kind", "hash",
		"name", "updater", "description", "issued", "links", "severity", "normalized_severity",
		"package_name", "package_version", "package_module", "package_arch", "package_kind",
		"dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id",
		"dist_arch", "dist_cpe", "dist_pretty_name",
		"repo_name", "repo_key", "repo_uri",
		"fixed_in_version", "arch_operation", "version_kind", "vulnerable_range", "not_vulnerable",
	}
	tmpAliasColumns = []string{"hash_kind", "hash", "namespace", "name", "is_self"}
)

const (
	// createStagingTables creates the per-transaction staging tables. ON COMMIT
	// DROP removes them automatically when the enclosing transaction ends.
	createStagingTables = `
CREATE TEMP TABLE tmp_vuln (
  hash_kind TEXT, hash BYTEA,
  name TEXT, updater TEXT, description TEXT, issued timestamptz, links TEXT,
  severity TEXT, normalized_severity TEXT,
  package_name TEXT, package_version TEXT, package_module TEXT, package_arch TEXT, package_kind TEXT,
  dist_id TEXT, dist_name TEXT, dist_version TEXT, dist_version_code_name TEXT, dist_version_id TEXT,
  dist_arch TEXT, dist_cpe TEXT, dist_pretty_name TEXT,
  repo_name TEXT, repo_key TEXT, repo_uri TEXT,
  fixed_in_version TEXT, arch_operation TEXT, version_kind TEXT,
  vulnerable_range VersionRange, not_vulnerable BOOL
) ON COMMIT DROP;
CREATE TEMP TABLE tmp_alias (
  hash_kind TEXT, hash BYTEA, namespace TEXT, name TEXT, is_self BOOL
) ON COMMIT DROP;`

	// stagingInsertVuln inserts the staged vulnerabilities. Duplicate
	// (hash_kind, hash) rows within the batch and rows already present are
	// silently ignored via ON CONFLICT DO NOTHING, matching the previous
	// per-row insert semantics.
	stagingInsertVuln = `
INSERT INTO vuln (
  hash_kind, hash, name, updater, description, issued, links, severity, normalized_severity,
  package_name, package_version, package_module, package_arch, package_kind,
  dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
  repo_name, repo_key, repo_uri, fixed_in_version, arch_operation, version_kind, vulnerable_range, not_vulnerable)
SELECT
  hash_kind, hash, name, updater, description, issued, links, severity, normalized_severity,
  package_name, package_version, package_module, package_arch, package_kind,
  dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
  repo_name, repo_key, repo_uri, fixed_in_version, arch_operation, version_kind,
  COALESCE(vulnerable_range, VersionRange('{}', '{}', '()')), not_vulnerable
FROM tmp_vuln
ON CONFLICT (hash_kind, hash) DO NOTHING;`

	// stagingAssocVuln associates every staged vulnerability with the current
	// update operation ($1).
	stagingAssocVuln = `
INSERT INTO uo_vuln (uo, vuln)
SELECT $1, v.id
FROM vuln v
JOIN (SELECT DISTINCT hash_kind, hash FROM tmp_vuln) t
  ON v.hash_kind = t.hash_kind AND v.hash = t.hash
ON CONFLICT DO NOTHING;`

	stagingInsertAliasNamespace = `
INSERT INTO alias_namespace (namespace)
SELECT DISTINCT namespace FROM tmp_alias
ON CONFLICT DO NOTHING;`

	stagingInsertAlias = `
INSERT INTO alias (namespace, name)
SELECT DISTINCT ns.id, t.name
FROM tmp_alias t
JOIN alias_namespace ns ON ns.namespace = t.namespace
ON CONFLICT DO NOTHING;`

	stagingInsertVulnerabilityAlias = `
INSERT INTO vulnerability_alias (vulnerability, alias)
SELECT DISTINCT v.id, a.id
FROM tmp_alias t
JOIN vuln v ON v.hash_kind = t.hash_kind AND v.hash = t.hash
JOIN alias_namespace ns ON ns.namespace = t.namespace
JOIN alias a ON a.namespace = ns.id AND a.name = t.name
WHERE NOT t.is_self
ON CONFLICT DO NOTHING;`

	stagingInsertVulnerabilitySelf = `
INSERT INTO vulnerability_self (vulnerability, self)
SELECT DISTINCT v.id, a.id
FROM tmp_alias t
JOIN vuln v ON v.hash_kind = t.hash_kind AND v.hash = t.hash
JOIN alias_namespace ns ON ns.namespace = t.namespace
JOIN alias a ON a.namespace = ns.id AND a.name = t.name
WHERE t.is_self
ON CONFLICT (vulnerability) DO NOTHING;`
)

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
		refreshView   = `REFRESH MATERIALIZED VIEW CONCURRENTLY latest_update_operations;`
	)

	var uoID uint64
	var ref uuid.UUID

	start := time.Now()

	// Pin the isolation level to "read committed" rather than inheriting
	// default_transaction_isolation. All vulnerability and alias writes now
	// happen inside this single transaction (via COPY into staging tables plus
	// set-based INSERT ... SELECT), so we no longer rely on cross-connection
	// visibility the way the previous out-of-transaction alias inserts did; but
	// the staging INSERT ... SELECT statements are still simplest to reason
	// about at READ COMMITTED, and pinning it keeps behaviour stable regardless
	// of the server's configured default.
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
			for v := range vulnIter {
				// If we have an existing vuln in the new batch
				// delete it from the oldVulns map so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, v.Name)
			}
			for delName := range delIter {
				// If we have an existing vuln that has been signaled
				// as deleted by the updater then delete it so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, delName)
			}
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

	// Bulk-load vulnerabilities and their aliases via COPY into per-transaction
	// TEMP staging tables, then set-based INSERT ... SELECT statements.
	//
	// This replaces a previous design that issued, per vulnerability, an
	// individual INSERT + SELECT-by-hash plus a callback-chain of per-alias
	// INSERT/SELECT/associate statements smeared across two connections. For a
	// full vulnerability bundle that meant tens of millions of round-trip-bound
	// statements, which left most CPU idle waiting on the network and made an
	// initial load take the better part of an hour. COPY + a handful of
	// set-based statements per batch keeps the same on-disk result while doing
	// the work in bulk. See ROX-XXXXX.
	skipCt := 0
	vulnCt := 0
	start = time.Now()

	if _, err := tx.Exec(ctx, createStagingTables); err != nil {
		return uuid.Nil, fmt.Errorf("creating staging tables: %w", err)
	}

	// copyBatchLim bounds how many vulnerabilities are buffered in memory (and
	// held in the staging tables) before being flushed with COPY + set-based
	// inserts. Keeping batches modest bounds memory/temp usage (the matcher runs
	// under a tight memory budget and has OOMed on this workload) while staying
	// large enough that per-batch statement overhead and round-trips amortise.
	copyBatchLim := copyBatchSize()
	vulnRows := make([][]any, 0, copyBatchLim)
	aliasRows := make([][]any, 0, copyBatchLim*4)

	flush := func() error {
		if len(vulnRows) == 0 {
			return nil
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_vuln"}, tmpVulnColumns, pgx.CopyFromRows(vulnRows)); err != nil {
			return fmt.Errorf("copying into tmp_vuln: %w", err)
		}
		if len(aliasRows) > 0 {
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_alias"}, tmpAliasColumns, pgx.CopyFromRows(aliasRows)); err != nil {
				return fmt.Errorf("copying into tmp_alias: %w", err)
			}
		}
		for _, q := range []struct {
			name string
			sql  string
			args []any
		}{
			{"insert_vuln", stagingInsertVuln, nil},
			{"assoc_vuln", stagingAssocVuln, []any{uoID}},
			{"insert_alias_namespace", stagingInsertAliasNamespace, nil},
			{"insert_alias", stagingInsertAlias, nil},
			{"insert_vulnerability_alias", stagingInsertVulnerabilityAlias, nil},
			{"insert_vulnerability_self", stagingInsertVulnerabilitySelf, nil},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return fmt.Errorf("staging %s: %w", q.name, err)
			}
		}
		if _, err := tx.Exec(ctx, `TRUNCATE tmp_vuln, tmp_alias;`); err != nil {
			return fmt.Errorf("truncating staging tables: %w", err)
		}
		vulnRows = vulnRows[:0]
		aliasRows = aliasRows[:0]
		return nil
	}

	// md5 hashing and building the COPY row values are pure per-record CPU work
	// and dominate a large initial load. Fan them out across workers while a
	// single collector owns the transaction and performs the COPY + set-based
	// inserts, so the DB side stays sequential and the operation remains a single
	// transaction. Record order does not matter: the result is a content-
	// deduplicated set (ON CONFLICT + set-based inserts).
	workers := copyWorkers()

	type built struct {
		vuln  []any
		alias [][]any
	}
	// Buffers are sized so workers can run ahead while the collector is blocked on
	// a batch flush (COPY + set-based inserts).
	// Small, bounded buffers: the DB write is the bottleneck, so letting the
	// build workers race far ahead of the collector would only accumulate built
	// rows in memory without improving throughput.
	jobCh := make(chan *claircore.Vulnerability, workers*4)
	resCh := make(chan built, workers*16)

	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	var (
		firstErr atomic.Pointer[error]
		vc, sc   atomic.Int64
	)
	setErr := func(e error) {
		firstErr.CompareAndSwap(nil, &e)
		wcancel()
	}

	// Workers: build rows.
	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for v := range jobCh {
				vr, ar := buildCopyRows(v)
				select {
				case resCh <- built{vr, ar}:
				case <-wctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		workerWG.Wait()
		close(resCh)
	}()

	// Dispatcher: pull vulnerabilities from the iterator and hand them to workers.
	go func() {
		defer close(jobCh)
		for vuln, iterErr := range vulnIter {
			if iterErr != nil {
				setErr(fmt.Errorf("iterating on vulnerabilities: %w", iterErr))
				return
			}
			vc.Add(1)
			if skipVulnerability(vuln) {
				sc.Add(1)
				continue
			}
			select {
			case jobCh <- vuln:
			case <-wctx.Done():
				return
			}
		}
	}()

	// Collector: owns tx, buffers built rows, and flushes in batches.
	for b := range resCh {
		vulnRows = append(vulnRows, b.vuln)
		aliasRows = append(aliasRows, b.alias...)
		if len(vulnRows) >= copyBatchLim {
			if err := flush(); err != nil {
				setErr(err)
				break
			}
		}
	}
	// Drain any results still in flight after an error so workers can exit.
	for range resCh { //nolint:revive // intentional drain
	}
	if ep := firstErr.Load(); ep != nil {
		return uuid.Nil, *ep
	}
	if err := flush(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish bulk vulnerability insert: %w", err)
	}
	vulnCt = int(vc.Load())
	skipCt = int(sc.Load())

	updateVulnerabilitiesCounter.WithLabelValues("insert_batch", strconv.FormatBool(delta)).Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("insert_batch", strconv.FormatBool(delta)).Observe(time.Since(start).Seconds())
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

// buildCopyRows computes the vulnerability's content hash and builds the COPY row
// values for the staging tables. It is a pure function of its input so it can be
// run concurrently from multiple workers. The returned vulnerability row's column
// order MUST match tmpVulnColumns; the alias rows' order MUST match
// tmpAliasColumns.
func buildCopyRows(vuln *claircore.Vulnerability) (vulnRow []any, aliasRows [][]any) {
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

	vulnRow = []any{
		hashKind, hash,
		vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
		pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
		dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
		repo.Name, repo.Key, repo.URI,
		vuln.FixedInVersion, vuln.ArchOperation, rangekind(vuln.Range), vuln.Range,
		vuln.Invert,
	}
	if n := len(vuln.Aliases); n > 0 {
		aliasRows = make([][]any, 0, n+1)
	}
	for _, a := range vuln.Aliases {
		if !a.Valid() {
			continue
		}
		aliasRows = append(aliasRows, []any{hashKind, hash, a.Space.Value(), a.Name, false})
	}
	if vuln.Self.Valid() {
		aliasRows = append(aliasRows, []any{hashKind, hash, vuln.Self.Space.Value(), vuln.Self.Name, true})
	}
	return vulnRow, aliasRows
}

// defaultCopyWorkers is 1: row-building runs on the collector goroutine by
// default. Parallel row-building is opt-in because (a) the workload is ultimately
// bottlenecked on the single database connection doing the writes, so it buys
// little, and (b) parallel building assigns vuln ids in a non-deterministic order,
// which is fine for matching (results are a content-deduplicated set) but changes
// the row order observed by order-sensitive consumers such as GetUpdateDiff.
const defaultCopyWorkers = 1

// copyWorkers returns the number of workers used to build COPY rows. It defaults
// to defaultCopyWorkers and can be raised with CLAIRCORE_COPY_WORKERS on
// CPU-bound, high-latency-database deployments where parallel row-building helps.
// A value <= 1 keeps row-building on the collector goroutine (deterministic
// order).
func copyWorkers() int {
	if v := os.Getenv("CLAIRCORE_COPY_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	n := runtime.GOMAXPROCS(0)
	if n > defaultCopyWorkers {
		n = defaultCopyWorkers
	}
	if n < 1 {
		n = 1
	}
	return n
}

// copyBatchSize returns the number of vulnerabilities buffered per COPY flush.
// It can be overridden with CLAIRCORE_COPY_BATCH to trade memory for fewer, larger
// batches (e.g. against a high-latency remote database).
func copyBatchSize() int {
	const def = 10000
	if v := os.Getenv("CLAIRCORE_COPY_BATCH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// SkipVulnerability reports if the provided [claircore.Vulnerability] should
// not be uploaded to the database.
func skipVulnerability(v *claircore.Vulnerability) bool {
	// TODO(hank) Check the vulnerability aliases. This requires *all* the
	// updaters being touched.
	return v.Package == nil || v.Package.Name == ""
}

func rangekind(r *claircore.Range) (kind string) {
	if r == nil || r.Lower.Kind != r.Upper.Kind {
		return ""
	}
	return r.Lower.Kind
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
