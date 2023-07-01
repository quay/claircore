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

type HashData struct {
	HashKind string
	Hash     interface{}
}

// UpdateVulnerabilities implements vulnstore.Updater.
//
// It creates a new UpdateOperation for this update call, inserts the
// provided vulnerabilities and computes a diff comprising the removed
// and added vulnerabilities for this UpdateOperation.
func (s *MatcherStore) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	const (
		// Create makes a new update operation and returns the reference and ID.
		create = `INSERT INTO update_operation (updater, fingerprint, kind) VALUES ($1, $2, 'vulnerability') RETURNING id, ref;`
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
		undo = `DELETE FROM update_operation WHERE id = $1;`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/updateVulnerabilities")

	var id uint64
	var ref uuid.UUID

	start := time.Now()

	if err := s.pool.QueryRow(ctx, create, updater, string(fingerprint)).Scan(&id, &ref); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}
	var success bool
	defer func() {
		if !success {
			if _, err := s.pool.Exec(ctx, undo, id); err != nil {
				zlog.Error(ctx).
					Err(err).
					Stringer("ref", ref).
					Msg("unable to remove update operation")
			}
		}
	}()

	updateVulnerabilitiesCounter.WithLabelValues("create").Add(1)
	updateVulnerabilitiesDuration.WithLabelValues("create").Observe(time.Since(start).Seconds())

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("update_operation created")

	// batch insert vulnerabilities
	skipCt := 0
	start = time.Now()
	batchSize := 1000
	totalVulns := len(vulns)
	numBatches := (totalVulns + batchSize - 1) / batchSize
	mBatcher := microbatch.NewInsert(tx, 1000, time.Minute)
	for batchIndex := 0; batchIndex < numBatches; batchIndex++ {
		// Insert attempts to create a new vulnerabilities. It fails silently.
		insert_query := `
		INSERT INTO vuln (
			hash_kind, hash,
			name, updater, description, issued, links, severity, normalized_severity,
			package_name, package_version, package_module, package_arch, package_kind,
			dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
			repo_name, repo_key, repo_uri,
			fixed_in_version, arch_operation, version_kind, vulnerable_range
		) VALUES %s
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		insert_values := []interface{}{}
		assoc_values := []HashData{}
		placeholders := []string{}
		startIndex := batchIndex * batchSize
		endIndex := (batchIndex + 1) * batchSize
		if endIndex > totalVulns {
			endIndex = totalVulns
		}
		j := 0
		for i := startIndex; i < endIndex; i++ {
			vuln := vulns[i]
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
			rowValues := fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, VersionRange($%d, $%d))", j*30+1, j*30+2, j*30+3, j*30+4, j*30+5, j*30+6, j*30+7, j*30+8, j*30+9, j*30+10, j*30+11, j*30+12, j*30+13, j*30+14, j*30+15, j*30+16, j*30+17, j*30+18, j*30+19, j*30+20, j*30+21, j*30+22, j*30+23, j*30+24, j*30+25, j*30+26, j*30+27, j*30+28, j*30+29, j*30+30)
			placeholders = append(placeholders, rowValues)
			insert_values = append(insert_values, hashKind, hash,
				vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
				pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
				dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
				repo.Name, repo.Key, repo.URI,
				vuln.FixedInVersion, vuln.ArchOperation, vKind, vrLower, vrUpper)
			hashData := HashData{
				HashKind: hashKind,
				Hash: hash,
			}
			assoc_values = append(assoc_values, hashData)
			j += 1
		}
		bulkValues := strings.Join(placeholders, ", ")
		insert_query = fmt.Sprintf(insert_query, bulkValues)
		if len(insert_values) == 0 {
			zlog.Debug(ctx).Msg("Bulk operations omitted because of no data")
		} else {
			_, err = s.pool.Exec(context.Background(), insert_query, insert_values...)
			if err != nil {
				return uuid.Nil, fmt.Errorf("failed to perform bulk insert vulnerabilities: %w", err)
			}
		}
		for _, hashData := range assoc_values {
			if err := mBatcher.Queue(ctx, assoc, hashData.HashKind, hashData.Hash, id); err != nil {
				return uuid.Nil, fmt.Errorf("failed to queue association: %w", err)
			}
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
	success = true
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