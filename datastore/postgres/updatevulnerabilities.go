package postgres

import (
	"context"
	_ "embed" // for queries
	"errors"
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

	// The isolation level must be pinned to "read committed" (rather than
	// inheriting default_transaction_isolation) because some INSERT ... SELECT
	// statements need to see alias rows committed outside this transaction
	// after it began.
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

	// batch insert vulnerabilities
	const batchLim = 1000
	skipCt := 0
	vulnCt := 0
	start = time.Now()
	// This is an annoying way to go about this, but c'est la vie.
	//
	// These batches are chains of statements smeared across two database
	// connections that are all connected via callbacks.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to acquire alias connection: %w", err)
	}
	defer conn.Release()
	// These are the batches used in the callback chain. The results of one are
	// used to enqueue queries into the next batch.
	//
	// They MUST be sent in this order, and [aliasBatch] MUST be sent outside
	// the transaction.
	var insertBatch, aliasBatch, assocBatch pgx.Batch
	// Some guesses at initial sizing. These should always level off, but
	// avoiding allocations and copies is always welcome.
	insertBatch.QueuedQueries = make([]*pgx.QueuedQuery, 0, batchLim+1)
	aliasBatch.QueuedQueries = make([]*pgx.QueuedQuery, 0, batchLim*4)
	assocBatch.QueuedQueries = make([]*pgx.QueuedQuery, 0, batchLim*5)
	// Flush sends the batches in the correct order, then resets the batches'
	// query slices.
	flush := func() (err error) {
		err = errors.Join(
			tx.SendBatch(ctx, &insertBatch).Close(),
			conn.SendBatch(ctx, &aliasBatch).Close(),
			tx.SendBatch(ctx, &assocBatch).Close(),
		)
		for _, b := range []*pgx.Batch{&insertBatch, &aliasBatch, &assocBatch} {
			clear(b.QueuedQueries)
			b.QueuedQueries = b.QueuedQueries[:0]
		}
		return err
	}

	// SeenSpace tracks alias namespaces, to avoid sending a lot of redundant
	// namespace creation statements.
	seenSpace := make(map[unique.Handle[string]]struct{})
	// This whole function is a giant callback hell. Don't do this. I was backed
	// into a corner. This function makes my son cry and actively saps joy from
	// the world.
	vulnIDCallback := func(vuln *claircore.Vulnerability) func(pgx.Row) error {
		// VulnID is where the id for the passed-in vulnerability will be
		// stored.
		var vulnID uint64
		// DoAlias is a closure that enqueues the Alias insertion statements.
		doAlias := func(a claircore.Alias, assoc string) {
			if !a.Valid() {
				return
			}
			if _, ok := seenSpace[a.Space]; !ok {
				seenSpace[a.Space] = struct{}{}
				aliasBatch.Queue(updateVulnerabilitiesInsertAliasNamespace, a.Space)
			}
			// It might be possible to collapse these two statements, at the
			// cost of making it more complicated: INSERT ... RETURNING only
			// works if an insertion happened.
			aliasBatch.Queue(updateVulnerabilitiesInsertAlias, a.Space, a.Name)
			aliasBatch.
				Queue(updateVulnerabilitiesSelectAlias, a.Space, a.Name).
				QueryRow(func(row pgx.Row) error {
					// This closure enqueues the statement to associate the
					// alias and the vulnerability via the correct pivot table.
					var aliasID uint64
					if err := row.Scan(&aliasID); err != nil {
						return err
					}
					if vulnID != 0 {
						assocBatch.Queue(assoc, vulnID, aliasID)
					}
					return nil
				})
		}
		for _, a := range vuln.Aliases {
			doAlias(a, updateVulnerabilitiesInsertVulnerabilityAlias)
		}
		doAlias(vuln.Self, updateVulnerabilitiesInsertVulnerabilitySelf)
		// All the above should make it so that the [*claircore.Vulnerability]
		// isn't pinned in memory until the batch is processed. Only the string
		// backing storage and the [unique.Handle] backing storage should be
		// unreclaimable while this batch is in flight.

		// As long as [insertBatch] is submitted first, [vulnID] is populated in
		// this callback and the [aliasBatch] callbacks have the value to use to
		// populate the [assocBatch].
		return func(row pgx.Row) error {
			if err := row.Scan(&vulnID); err != nil {
				return err
			}
			assocBatch.Queue(updateVulnerabilitiesAssociateUpdateOperationVuln, uoID, vulnID)
			return nil
		}
	}

	for vuln, iterErr := range vulnIter {
		if iterErr != nil {
			err = iterErr
			break
		}
		vulnCt++
		if skipVulnerability(vuln) {
			skipCt++
			continue
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

		insertBatch.Queue(
			updateVulnerabilitiesInsertVuln,
			hashKind, hash,
			vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, rangekind(vuln.Range), vuln.Range,
			vuln.Invert,
		)
		insertBatch.Queue(updateVulnerabilitiesSelectVulnByHash, hashKind, hash).QueryRow(vulnIDCallback(vuln))

		if ct := insertBatch.Len(); ct >= batchLim {
			if err = flush(); err != nil {
				err = fmt.Errorf("failed batching: %w", err)
				break
			}
		}
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("iterating on vulnerabilities: %w", err)
	}
	if err := flush(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish batch vulnerability insert: %w", err)
	}

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
