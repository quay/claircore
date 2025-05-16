package postgres

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/microbatch"
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
			Help:      "Total number of database queries issued in the updateVulnerabilities method.",
		},
		[]string{"query", "is_delta"},
	)
	updateVulnerabilitiesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updatevulnerabilities_duration_seconds",
			Help:      "The duration of all queries issued in the updateVulnerabilities method",
		},
		[]string{"query", "is_delta"},
	)
)

// UpdateVulnerabilitiesIter implements vulnstore.Updater.
func (s *MatcherStore) UpdateVulnerabilitiesIter(ctx context.Context, updater string, fp driver.Fingerprint, it datastore.VulnerabilityIter) (uuid.UUID, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/MatcherStore.UpdateVulnerabilitiesIter")
	return s.updateVulnerabilities(ctx, updater, fp, it, nil)
}

// UpdateVulnerabilities implements vulnstore.Updater.
//
// It creates a new UpdateOperation for this update call, inserts the
// provided vulnerabilities and computes a diff comprising the removed
// and added vulnerabilities for this UpdateOperation.
func (s *MatcherStore) UpdateVulnerabilities(ctx context.Context, updater string, fp driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/MatcherStore.UpdateVulnerabilities")
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
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/MatcherStore.DeltaUpdateVulnerabilities")
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
			fixed_in_version, arch_operation, version_kind, vulnerable_range
		) VALUES (
		  $1, $2,
		  $3, $4, $5, $6, $7, $8, $9,
		  $10, $11, $12, $13, $14,
		  $15, $16, $17, $18, $19, $20, $21, $22,
		  $23, $24, $25,
		  $26, $27, $28, COALESCE($29, VersionRange('{}', '{}', '()'))
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
	)

	var uoID uint64
	var ref uuid.UUID

	start := time.Now()

	tx, err := s.pool.Begin(ctx)
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

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("update_operation created")

	if delta {
		ctx = zlog.ContextWithValues(ctx, "mode", "delta")
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

	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute)

	vulnIter(func(vuln *claircore.Vulnerability, iterErr error) bool {
		if iterErr != nil {
			err = iterErr
			return false
		}
		vulnCt++
		if vuln.Package == nil || vuln.Package.Name == "" {
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

		err = mBatcher.Queue(ctx, insert,
			hashKind, hash,
			vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, vKind, vuln.Range,
		)
		if err != nil {
			err = fmt.Errorf("failed to queue vulnerability: %w", err)
			return false
		}

		err = mBatcher.Queue(ctx, assoc, hashKind, hash, uoID)
		if err != nil {
			err = fmt.Errorf("failed to queue association: %w", err)
			return false
		}

		return true
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("iterating on vulnerabilities: %w", err)
	}
	if err := mBatcher.Done(ctx); err != nil {
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

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Int("skipped", skipCt).
		Int("inserted", vulnCt-skipCt).
		Msg("update_operation committed")
	return ref, nil
}

// Md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *claircore.Vulnerability) (string, []byte) {
	var b bytes.Buffer
	b.WriteString(v.Name)
	b.WriteString(v.Description)
	b.WriteString(v.Issued.String())
	b.WriteString(v.Links)
	b.WriteString(v.Severity)
	if v.Package != nil {
		b.WriteString(v.Package.Name)
		b.WriteString(v.Package.Version)
		b.WriteString(v.Package.Module)
		b.WriteString(v.Package.Arch)
		b.WriteString(v.Package.Kind)
	}
	if v.Dist != nil {
		b.WriteString(v.Dist.DID)
		b.WriteString(v.Dist.Name)
		b.WriteString(v.Dist.Version)
		b.WriteString(v.Dist.VersionCodeName)
		b.WriteString(v.Dist.VersionID)
		b.WriteString(v.Dist.Arch)
		b.WriteString(v.Dist.CPE.BindFS())
		b.WriteString(v.Dist.PrettyName)
	}
	if v.Repo != nil {
		b.WriteString(v.Repo.Name)
		b.WriteString(v.Repo.Key)
		b.WriteString(v.Repo.URI)
	}
	b.WriteString(v.ArchOperation.String())
	b.WriteString(v.FixedInVersion)
	if k, l, u := rangefmt(v.Range); k != nil {
		b.WriteString(*k)
		b.WriteString(l)
		b.WriteString(u)
	}
	s := md5.Sum(b.Bytes())
	return "md5", s[:]
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
	for i := 0; i < 10; i++ {
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
	for i := 0; i < 10; i++ {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	upper = buf.String()

	return kind, lower, upper
}
