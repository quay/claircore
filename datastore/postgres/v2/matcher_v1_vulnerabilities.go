package postgres

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

// Get implements [datastore.MatcherV1Vulnerability].
func (s *MatcherV1) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.MatcherV1VulnerabilityGetOpts) (_ map[string][]*claircore.Vulnerability, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	// Current semantics is that callers must match on package name.
	// Whether that's a good idea is up for debate.
	cs := make([]driver.MatchConstraint, len(opts.Matchers)+1)
	cs[0] = driver.PackageName
	copy(cs[1:], opts.Matchers)
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	cs = compact(cs)
	va := newVulnArena()
	zlog.Debug(ctx).
		Int("count", len(records)).
		Stringers("constraints", stringers(cs)).
		Msg("fetching vulnerabilities")

	err = pgx.BeginTxFunc(ctx, s.pool, txRO, s.call(ctx, `get`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
		var batch pgx.Batch
		for _, record := range records {
			batch.Queue(query,
				constraint(cs, record, driver.PackageName),                 // $1
				constraint(cs, record, driver.PackageSourceName),           // $2
				constraint(cs, record, driver.PackageModule),               // $3
				constraint(cs, record, driver.DistributionDID),             // $4
				constraint(cs, record, driver.DistributionName),            // $5
				constraint(cs, record, driver.DistributionVersionID),       // $6
				constraint(cs, record, driver.DistributionVersion),         // $7
				constraint(cs, record, driver.DistributionVersionCodeName), // $8
				constraint(cs, record, driver.DistributionPrettyName),      // $9
				constraint(cs, record, driver.DistributionCPE),             // $10
				constraint(cs, record, driver.DistributionArch),            // $11
				constraint(cs, record, driver.RepositoryName),              // $12
				normVersionKind(opts.VersionFiltering, record),             // $13
				normVersion(opts.VersionFiltering, record),                 // $14
			)
		}
		res := tx.SendBatch(ctx, &batch)
		// Make sure to assign to "err" and then return so that the defer can
		// add if need be.
		defer func() {
			err = errors.Join(err, res.Close())
		}()
		trace.SpanFromContext(ctx).AddEvent("queries submitted")

		var rowct int
		for _, record := range records {
			var rows pgx.Rows
			rows, err = res.Query()
			if err != nil {
				err = fmt.Errorf("unable to read query results: %w", err)
				return err
			}

			va.CurrentID(record.Package.ID)
			for rows.Next() {
				rowct++
				if err := rows.Scan(va); err != nil {
					err = fmt.Errorf("failed to scan vulnerability: %w", err)
					return err
				}
			}
		}
		zlog.Debug(ctx).
			Int("count", rowct).
			Msg("read rows")
		return nil
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	default:
		return nil, err
	}
	return va.Result(), nil
}

// TODO(hank) Use the [slices] package for the constraint preparation when
// go1.20 support is dropped.

// Compact is a port of [slices.Compact].
//
// Remove this when we can use go1.21.
func compact(s []driver.MatchConstraint) []driver.MatchConstraint {
	if len(s) < 2 {
		return s
	}
	i := 1
	for k := 1; k < len(s); k++ {
		if s[k] != s[k-1] {
			if i != k {
				s[i] = s[k]
			}
			i++
		}
	}
	return s[:i]
}

// Contstraint returns the correct value for the constraint "which," if it's in
// the constraint set "cs".
func constraint(cs []driver.MatchConstraint, r *claircore.IndexRecord, which driver.MatchConstraint) (ret *string) {
	// TODO(hank) Use [slices.Contains].
	contains := false
	for i := range cs {
		if which == cs[i] {
			contains = true
			break
		}
	}
	if !contains {
		return nil
	}
	switch which {
	case driver.PackageName, driver.PackageSourceName, driver.PackageModule:
		pkg := r.Package
		switch which {
		case driver.PackageName:
			ret = &pkg.Name
		case driver.PackageSourceName:
			src := pkg.Source
			ret = &src.Name
		case driver.PackageModule:
			ret = &pkg.Module
		default:
			panic(fmt.Sprintf("unimplemented package match constraint: %v", which))
		}
	case driver.DistributionDID, driver.DistributionName, driver.DistributionVersion,
		driver.DistributionVersionCodeName, driver.DistributionVersionID,
		driver.DistributionArch, driver.DistributionCPE, driver.DistributionPrettyName:
		dist := r.Distribution
		switch which {
		case driver.DistributionDID:
			ret = &dist.DID
		case driver.DistributionName:
			ret = &dist.Name
		case driver.DistributionVersion:
			ret = &dist.Version
		case driver.DistributionVersionCodeName:
			ret = &dist.VersionCodeName
		case driver.DistributionVersionID:
			ret = &dist.VersionID
		case driver.DistributionArch:
			ret = &dist.Arch
		case driver.DistributionCPE:
			ret = new(string)
			*ret = dist.CPE.BindFS()
		case driver.DistributionPrettyName:
			ret = &dist.PrettyName
		default:
			panic(fmt.Sprintf("unimplemented distribution match constraint: %v", which))
		}
	case driver.RepositoryName:
		repo := r.Repository
		switch which {
		case driver.RepositoryName:
			ret = &repo.Name
		default:
			panic(fmt.Sprintf("unimplemented repository match constraint: %v", which))
		}
	default:
		panic(fmt.Sprintf("unimplemented match constraint: %v", which))
	}
	return ret
}

// NormVersion returns the encoded NormalizedVersion if "ok".
func normVersion(ok bool, r *claircore.IndexRecord) *string {
	if !ok {
		return nil
	}
	var lit strings.Builder
	v := r.Package.NormalizedVersion
	b := make([]byte, 0, 16)
	lit.WriteString("'{")
	for i := 0; i < 10; i++ {
		if i != 0 {
			lit.WriteByte(',')
		}
		lit.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	lit.WriteString("}'")
	ret := lit.String()
	return &ret
}

// NormVersionKind returns the NormalizedVersion Kind if "ok".
func normVersionKind(ok bool, r *claircore.IndexRecord) *string {
	if !ok {
		return nil
	}
	return &r.Package.NormalizedVersion.Kind
}

func stringers[E fmt.Stringer, S ~[]E](s S) []fmt.Stringer {
	ret := make([]fmt.Stringer, len(s))
	for i := range s {
		ret[i] = s[i]
	}
	return ret
}

var (
	zeroRepo claircore.Repository
	zeroDist claircore.Distribution
)

// UpdateVulnerabilities implements [vulnstore.Updater].
//
// It creates a new UpdateOperation for this update call, inserts the
// provided vulnerabilities and computes a diff comprising the removed
// and added vulnerabilities for this UpdateOperation.
func (s *MatcherV1) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (_ uuid.UUID, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	const hashKind = `md5`
	var ref uuid.UUID
	type todo struct {
		Vulnerability *claircore.Vulnerability
		Digest        []byte
	}
	todos := make([]todo, 0, len(vulns))
	for _, v := range vulns {
		if v.Package == nil || v.Package.Name == "" {
			continue
		}
		_, d := md5Vuln(v)
		todos = append(todos, todo{
			Vulnerability: v,
			Digest:        d,
		})
	}

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `UpdateVulnerabilities`, func(ctx context.Context, tx pgx.Tx) (err error) {
		var id int64

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `create`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			return s.pool.QueryRow(ctx, query, updater, string(fingerprint)).Scan(&id, &ref)
		}))
		if err != nil {
			return err
		}
		zlog.Debug(ctx).
			Str("ref", ref.String()).
			Msg("update_operation created")

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insert`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			var batch pgx.Batch
			for i, todo := range todos {
				vuln := todo.Vulnerability
				pkg := vuln.Package
				dist := vuln.Dist
				repo := vuln.Repo
				if dist == nil {
					dist = &zeroDist
				}
				if repo == nil {
					repo = &zeroRepo
				}
				vKind, vrLower, vrUpper := rangefmt(vuln.Range)

				batch.Queue(query,
					hashKind, todo.Digest,
					vuln.Name, vuln.Updater, vuln.Description, vuln.Issued, vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
					pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
					dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, dist.CPE, dist.PrettyName,
					repo.Name, repo.Key, repo.URI,
					vuln.FixedInVersion, vuln.ArchOperation, vKind, vrLower, vrUpper,
				)

				if i%2000 == 0 && batch.Len() != 0 {
					res := tx.SendBatch(ctx, &batch)
					for n, lim := 0, batch.Len(); n < lim; n++ {
						if _, err := res.Exec(); err != nil {
							return fmt.Errorf("failed to queue vulnerability: %w", err)
						}
					}
					if err := res.Close(); err != nil {
						return err
					}
					batch = pgx.Batch{}
				}
			}
			res := tx.SendBatch(ctx, &batch)
			for n, lim := 0, batch.Len(); n < lim; n++ {
				if _, err := res.Exec(); err != nil {
					return fmt.Errorf("failed to queue vulnerability: %w", err)
				}
			}
			return res.Close()
		}))
		if err != nil {
			return err
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `associate`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			var batch pgx.Batch
			for i, todo := range todos {
				batch.Queue(query, hashKind, todo.Digest, id)

				if i%2000 == 0 && batch.Len() != 0 {
					res := tx.SendBatch(ctx, &batch)
					for n, lim := 0, batch.Len(); n < lim; n++ {
						if _, err := res.Exec(); err != nil {
							return fmt.Errorf("failed to queue association: %w", err)
						}
					}
					if err := res.Close(); err != nil {
						return err
					}
					batch = pgx.Batch{}
				}
			}
			res := tx.SendBatch(ctx, &batch)
			for n, lim := 0, batch.Len(); n < lim; n++ {
				if _, err := res.Exec(); err != nil {
					return fmt.Errorf("failed to queue association: %w", err)
				}
			}
			return res.Close()
		}))
		if err != nil {
			return err
		}

		return nil
	}))
	switch {
	case errors.Is(err, nil):
		zlog.Debug(ctx).
			Str("ref", ref.String()).
			Int("skipped", len(vulns)-len(todos)).
			Int("inserted", len(todos)).
			Msg("update_operation committed")
	default:
		return uuid.Nil, err
	}

	s.pool.AcquireFunc(ctx, s.acquire(ctx, `refresh`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		if _, err := c.Exec(ctx, query); err != nil {
			span := trace.SpanFromContext(ctx)
			span.SetStatus(codes.Error, "refresh failed")
			span.RecordError(fmt.Errorf("could not refresh latest_update_operations: %w", err))
		}
		return nil
	}))

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
