package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore"
)

var (
	// ErrNotIndexed indicates the vulnerability being queried has a dist or repo not
	// indexed into the database.
	ErrNotIndexed = fmt.Errorf("vulnerability containers data not indexed by any scannners")
)

// AffectedManifests finds the manifests digests which are affected by the provided vulnerability.
//
// An exhaustive search for all indexed packages of the same name as the vulnerability is performed.
//
// The list of packages is filtered down to only the affected set.
//
// The manifest index is then queried to resolve a list of manifest hashes containing the affected
// artifacts.
func (s *IndexerV1) AffectedManifests(ctx context.Context, v claircore.Vulnerability, vulnFunc claircore.CheckVulnernableFunc) (_ []claircore.Digest, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	ctx = zlog.ContextWithValues(ctx, "vulnerability", v.Name)

	out := []claircore.Digest{}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly},
		s.tx(ctx, `AffectedManifests`, func(ctx context.Context, tx pgx.Tx) (err error) {
			var pr claircore.IndexRecord
			span := trace.SpanFromContext(ctx)

			err = pgx.BeginFunc(ctx, tx, s.tx(ctx, `protoRecord`, s.protoRecordCall(&pr, v)))
			switch {
			case err == nil:
			case errors.Is(err, ErrNotIndexed):
				// This is a common case: the system knows of a vulnerability but
				// doesn't know of any manifests it could apply to.
				zlog.Debug(ctx).Msg("not indexed")
				trace.SpanFromContext(ctx).SetStatus(codes.Ok, "not indexed")
				return nil
			default:
				return err
			}

			// Collect all packages which may be affected by the vulnerability
			// in question.
			pkgsToFilter := []claircore.Package{}

			err = pgx.BeginFunc(ctx, tx,
				s.call(ctx, `selectPackages`, func(ctx context.Context, tx pgx.Tx, query string) error {
					rows, err := tx.Query(ctx, query, v.Package.Name)
					if err != nil {
						return fmt.Errorf("vulnerability %q: %w", v.ID, err)
					}
					defer rows.Close()

					for rows.Next() {
						var pkg claircore.Package
						var id int64
						var nKind *string
						err := rows.Scan(
							&id,
							&pkg.Name,
							&pkg.Version,
							&pkg.Kind,
							&nKind,
							&pkg.NormalizedVersion,
							&pkg.Module,
							&pkg.Arch,
						)
						if err != nil {
							return fmt.Errorf("unmarshal error: %w", err)
						}
						idStr := strconv.FormatInt(id, 10)
						pkg.ID = idStr
						if nKind != nil {
							pkg.NormalizedVersion.Kind = *nKind
						}
						pkgsToFilter = append(pkgsToFilter, pkg)
					}
					trace.SpanFromContext(ctx).
						AddEvent("loaded packages", trace.WithAttributes(attribute.Int("count", len(pkgsToFilter))))
					zlog.Debug(ctx).Int("count", len(pkgsToFilter)).Msg("packages to filter")
					if err := rows.Err(); err != nil {
						return fmt.Errorf("error reading response: %w", err)
					}
					return nil
				}))
			if err != nil {
				return fmt.Errorf("unable to select packages: %w", err)
			}

			// for each package discovered create an index record
			// and determine if any in-tree matcher finds the record vulnerable
			var filteredRecords []claircore.IndexRecord
			for i := range pkgsToFilter {
				pkg := &pkgsToFilter[i]
				pr.Package = pkg
				var match bool
				var err error
				pprof.Do(ctx, pprof.Labels("hook", "CheckVulnFunc"), func(ctx context.Context) {
					match, err = vulnFunc(ctx, &pr, &v)
				})
				if err != nil {
					return fmt.Errorf("error in check vulnerable hook: %w", err)
				}
				if match {
					filteredRecords = append(filteredRecords, claircore.IndexRecord{
						Package:      pkg,
						Distribution: pr.Distribution,
						Repository:   pr.Repository,
					})
				}
			}
			span.AddEvent("filtered packages", trace.WithAttributes(attribute.Int("count", len(filteredRecords))))
			zlog.Debug(ctx).Int("count", len(filteredRecords)).Msg("vulnerable index records")
			// Query the manifest index for manifests containing the vulnerable
			// IndexRecords and create a set containing each unique manifest.
			set := map[string]struct{}{}
			selectAffected := func(id string, dist, repo *uint64) callFunc {
				return func(ctx context.Context, tx pgx.Tx, query string) error {
					rows, err := tx.Query(ctx, query, id, dist, repo)
					if err != nil {
						return err
					}
					defer rows.Close()
					for rows.Next() {
						var hash string
						if err := rows.Scan(&hash); err != nil {
							return err
						}
						if _, ok := set[hash]; ok {
							continue
						}
						set[hash] = struct{}{}
						i := len(out)
						out = append(out, claircore.Digest{})
						if err := out[i].UnmarshalText([]byte(hash)); err != nil {
							return err
						}
					}
					return rows.Err()
				}
			}

			for _, record := range filteredRecords {
				v, err := toValues(record)
				if err != nil {
					return fmt.Errorf("failed to get sql values for query: %w", err)
				}
				err = pgx.BeginFunc(ctx, tx, s.call(ctx, `selectAffected`, selectAffected(record.Package.ID, v[2], v[3])))
				switch {
				case errors.Is(err, nil):
				default:
					return fmt.Errorf("error selecting affected: %w", err)
				}
			}

			span.AddEvent("affected manifests", trace.WithAttributes(attribute.Int("count", len(out))))
			zlog.Debug(ctx).Int("count", len(out)).Msg("affected manifests")
			return nil
		}))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *IndexerV1) protoRecordCall(out *claircore.IndexRecord, v claircore.Vulnerability) txFunc {
	return func(ctx context.Context, tx pgx.Tx) error {
		// fill dist into prototype index record if exists
		if (v.Dist != nil) && (v.Dist.Name != "") {
			const name = `selectDist`
			var did int64
			err := pgx.BeginFunc(ctx, tx, s.call(ctx, name, protoRecordSelectDist(&did, v.Dist)))
			switch {
			case errors.Is(err, nil):
				id := strconv.FormatInt(did, 10)
				out.Distribution = &claircore.Distribution{
					ID:              id,
					Arch:            v.Dist.Arch,
					CPE:             v.Dist.CPE,
					DID:             v.Dist.DID,
					Name:            v.Dist.Name,
					PrettyName:      v.Dist.PrettyName,
					Version:         v.Dist.Version,
					VersionCodeName: v.Dist.VersionCodeName,
					VersionID:       v.Dist.VersionID,
				}
				zlog.Debug(ctx).Str("id", id).Msg("discovered distribution id")
			case errors.Is(err, pgx.ErrNoRows):
				// OK
			default:
				return fmt.Errorf("failed to scan dist: %w", err)
			}
		} else {
			zlog.Debug(ctx).Msg("no distribution")
		}

		// fill repo into prototype index record if exists
		if (v.Repo != nil) && (v.Repo.Name != "") {
			const name = `selectRepo`
			var rid int64
			err := pgx.BeginFunc(ctx, tx, s.call(ctx, name, protoRecordSelectRepo(&rid, v.Repo)))
			switch {
			case errors.Is(err, nil):
				id := strconv.FormatInt(rid, 10)
				out.Repository = &claircore.Repository{
					ID:   id,
					Key:  v.Repo.Key,
					Name: v.Repo.Name,
					URI:  v.Repo.URI,
				}
				zlog.Debug(ctx).Str("id", id).Msg("discovered repo id")
			case errors.Is(err, pgx.ErrNoRows):
				// OK
			default:
				return fmt.Errorf("failed to scan repo: %w", err)
			}
		} else {
			zlog.Debug(ctx).Msg("no repository")
		}

		// we need at least a repo or distribution to continue
		if (out.Distribution == nil) && (out.Repository == nil) {
			return ErrNotIndexed
		}
		return nil
	}
}

func protoRecordSelectDist(out *int64, d *claircore.Distribution) callFunc {
	return func(ctx context.Context, tx pgx.Tx, query string) error {
		return tx.QueryRow(ctx, query,
			d.Arch,
			d.CPE,
			d.DID,
			d.Name,
			d.PrettyName,
			d.Version,
			d.VersionCodeName,
			d.VersionID,
		).Scan(out)
	}
}

func protoRecordSelectRepo(out *int64, r *claircore.Repository) callFunc {
	return func(ctx context.Context, tx pgx.Tx, query string) error {
		return tx.QueryRow(ctx, query,
			r.Name,
			r.Key,
			r.URI,
		).Scan(out)
	}
}
