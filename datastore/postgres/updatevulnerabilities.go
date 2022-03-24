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
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
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
		[]string{"query"},
	)
	updateVulnerabilitiesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "vulnstore",
			Name:      "updatevulnerabilities_duration_seconds",
			Help:      "The duration of all queries issued in the updateVulnerabilities method",
		},
		[]string{"query"},
	)
)

// UpdateVulnerabilities creates a new UpdateOperation for this update call,
// inserts the provided vulnerabilities and computes a diff comprising the
// removed and added vulnerabilities for this UpdateOperation.
func updateVulnerabilites(ctx context.Context, pool *pgxpool.Pool, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	const (
		// Create makes a new update operation and returns the reference and ID.
		create = `INSERT INTO update_operation (updater, fingerprint, kind) VALUES ($1, $2, 'vulnerability') RETURNING id, ref;`
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
		  $26, $27, $28, VersionRange($29, $30)
		)
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		// Assoc associates an update operation and a vulnerability. It fails
		// silently.
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/updateVulnerabilities")

	tx, err := pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var id uint64
	var ref uuid.UUID

	start := time.Now()

	if err := pool.QueryRow(ctx, create, updater, string(fingerprint)).Scan(&id, &ref); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}

	updateVulnerabilitiesCounter.WithLabelValues("create").Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("create").Observe(time.Since(start).Seconds())

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("update_operation created")

	// batch insert vulnerabilities
	skipCt := 0

	start = time.Now()

	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute)
	for _, vuln := range vulns {
		if vuln.Package == nil || vuln.Package.Name == "" {
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
		vKind, vrLower, vrUpper := rangefmt(vuln.Range)

		err := mBatcher.Queue(ctx, insert,
			hashKind, hash,
			vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, vKind, vrLower, vrUpper,
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to queue vulnerability: %w", err)
		}

		if err := mBatcher.Queue(ctx, assoc, hashKind, hash, id); err != nil {
			return uuid.Nil, fmt.Errorf("failed to queue association: %w", err)
		}
	}
	if err := mBatcher.Done(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to finish batch vulnerability insert: %w", err)
	}

	updateVulnerabilitiesCounter.WithLabelValues("insert_batch").Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Int("skipped", skipCt).
		Int("inserted", len(vulns)-skipCt).
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
