package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"runtime/trace"
	"strconv"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/omnimatcher"
)

var (
	// ErrNotIndexed indicates the vulnerability being queried has a dist or repo not
	// indexed into the database.
	ErrNotIndexed = fmt.Errorf("vulnerability containers data not indexed by any scannners")

	affectedManifestsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "affectedmanifests_total",
			Help:      "Total number of database queries issued in the AffectedManifests method.",
		},
		[]string{"query"},
	)
	affectedManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "affectedmanifests_duration_seconds",
			Help:      "Duration of all queries issued in the AffectedManifests method.",
		},
		[]string{"query"},
	)
	protoRecordCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "protorecord_total",
			Help:      "Total number of database queries issued in the protoRecord method.",
		},
		[]string{"query"},
	)
	protoRecordDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "protorecord_duration_seconds",
			Help:      "Duration of all queries issued in the protoRecord method.",
		},
		[]string{"query"},
	)
)

var (
	//go:embed sql/select_dist.sql
	selectDistSQL string
	//go:embed sql/select_repo.sql
	selectRepoSQL string
	//go:embed sql/select_packages.sql
	selectPackagesSQL string
	//go:embed sql/select_affected.sql
	selectAffectedSQL string
)

// AffectedManifests finds the manifests digests which are affected by the provided vulnerability.
//
// An exhaustive search for all indexed packages of the same name as the vulnerability is performed.
//
// The list of packages is filtered down to only the affected set.
//
// The manifest index is then queried to resolve a list of manifest hashes containing the affected
// artifacts.
func (s *store) AffectedManifests(ctx context.Context, v claircore.Vulnerability) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/indexer/postgres/store.AffectedManifests")
	ctx, task := trace.NewTask(ctx, "AffectedManifests")
	defer task.End()

	var (
		pr       *claircore.IndexRecord
		toFilter []claircore.Package
	)
	eg, gctx := errgroup.WithContext(ctx)
	eg.Go(func() (err error) {
		// confirm the incoming vuln can be
		// resolved into a prototype index record
		pr, err = s.protoRecord(gctx, &v)
		switch {
		case err == nil:
		case errors.Is(err, ErrNotIndexed):
			// This is a common case: the system knows of a vulnerability but
			// doesn't know of any manifests it could apply to.
		default:
			return fmt.Errorf("error resolving index record: %w", err)
		}
		return nil
	})
	eg.Go(func() (err error) {
		// collect all packages which may be affected
		// by the vulnerability in question.
		toFilter, err = s.vulnerabilityToPackages(gctx, &v)
		if err != nil {
			return fmt.Errorf("error extracting packages: %w", err)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("error during preparation: %w", err)
	}

	// for each package discovered create an index record
	// and determine if any in-tree matcher finds the record vulnerable
	filteredRecords := make([]claircore.IndexRecord, 0, len(toFilter))
	om := omnimatcher.New(nil)
	for i := range toFilter {
		pkg := &toFilter[i]
		pr.Package = pkg
		match, err := om.Vulnerable(ctx, pr, &v)
		if err != nil {
			return nil, err
		}
		if match {
			filteredRecords = append(filteredRecords, claircore.IndexRecord{
				Package:      pkg,
				Distribution: pr.Distribution,
				Repository:   pr.Repository,
			})
		}
	}
	zlog.Debug(ctx).Int("count", len(filteredRecords)).Msg("vulnerable index records")

	// Query the manifest index for manifests containing the vulnerable
	// IndexRecords and create a set containing each unique manifest.
	set := map[string]struct{}{}
	out := []claircore.Digest{}
	// This could get parallelized if we were willing to do the duplication handling another way.
	for i := range filteredRecords {
		v, err := toValues(&filteredRecords[i])
		if err != nil {
			return nil, fmt.Errorf("failed to resolve record: %w", err)
		}
		err = s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			const name = "selectAffected"
			defer trace.StartRegion(ctx, name).End()
			defer prometheus.NewTimer(affectedManifestsDuration.WithLabelValues(name)).ObserveDuration()
			affectedManifestsCounter.WithLabelValues(name).Add(1)
			rows, err := c.Query(ctx,
				selectAffectedSQL,
				v.Package,
				v.Distribution,
				v.Repository,
			)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, pgx.ErrNoRows):
				err = fmt.Errorf("failed to query the manifest index: %w", err)
				fallthrough
			default:
				return err
			}
			defer rows.Close()

			for rows.Next() {
				var hash claircore.Digest
				err := rows.Scan(&hash)
				if err != nil {
					return fmt.Errorf("failed scanning manifest hash into digest: %w", err)
				}
				if _, ok := set[hash.String()]; !ok {
					set[hash.String()] = struct{}{}
					out = append(out, hash)
				}
			}
			return rows.Err()
		})
		if err != nil {
			return nil, err
		}
	}
	zlog.Debug(ctx).Int("count", len(out)).Msg("affected manifests")
	return out, nil
}

// protoRecord is a helper method which resolves a Vulnerability to an IndexRecord with no Package defined.
//
// it is an error for both a distribution and a repo to be missing from the Vulnerability.
func (s *store) protoRecord(ctx context.Context, v *claircore.Vulnerability) (*claircore.IndexRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/indexer/postgres/protoRecord")
	defer trace.StartRegion(ctx, "protoRecord").End()
	if v.Dist == nil && v.Repo == nil {
		return nil, errors.New("bad vulnerability: no distribution or repository")
	}
	var ret claircore.IndexRecord

	// fill dist into prototype index record if exists
	if (v.Dist != nil) && (v.Dist.Name != "") {
		var id pgtype.Int8
		err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			const name = "selectDist"
			defer trace.StartRegion(ctx, name).End()
			defer prometheus.NewTimer(protoRecordDuration.WithLabelValues(name)).ObserveDuration()
			protoRecordCounter.WithLabelValues(name).Add(1)
			return c.QueryRow(ctx,
				selectDistSQL,
				v.Dist.Arch,
				v.Dist.CPE,
				v.Dist.DID,
				v.Dist.Name,
				v.Dist.PrettyName,
				v.Dist.Version,
				v.Dist.VersionCodeName,
				v.Dist.VersionID,
			).Scan(&id)
		})
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return nil, fmt.Errorf("failed to scan dist: %w", err)
		}
		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			ret.Distribution = &claircore.Distribution{
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
		}
	}

	// fill repo into prototype index record if exists
	if (v.Repo != nil) && (v.Repo.Name != "") {
		var id pgtype.Int8
		err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			const name = "selectRepo"
			defer trace.StartRegion(ctx, name).End()
			defer prometheus.NewTimer(protoRecordDuration.WithLabelValues(name)).ObserveDuration()
			protoRecordCounter.WithLabelValues(name).Add(1)
			return c.QueryRow(ctx, selectRepoSQL,
				v.Repo.Name,
				v.Repo.Key,
				v.Repo.URI,
			).Scan(&id)
		})
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return nil, fmt.Errorf("failed to scan repo: %w", err)
		}
		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			ret.Repository = &claircore.Repository{
				ID:   id,
				Key:  v.Repo.Key,
				Name: v.Repo.Name,
				URI:  v.Repo.URI,
			}
			zlog.Debug(ctx).Str("id", id).Msg("discovered repo id")
		}
	}

	// we need at least a repo or distribution to continue
	if (ret.Distribution == nil) && (ret.Repository == nil) {
		return nil, ErrNotIndexed
	}

	return &ret, nil
}

func (s *store) vulnerabilityToPackages(ctx context.Context, v *claircore.Vulnerability) ([]claircore.Package, error) {
	const name = "vulnerabilityToPackages"
	defer trace.StartRegion(ctx, name).End()
	defer prometheus.NewTimer(affectedManifestsDuration.WithLabelValues(name)).ObserveDuration()
	affectedManifestsCounter.WithLabelValues(name).Add(1)
	rows, err := s.pool.Query(ctx, selectPackagesSQL, v.Package.Name)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to query packages associated with vulnerability %q: %w", v.ID, err)
	}
	defer rows.Close()
	var out []claircore.Package

	for rows.Next() {
		i := len(out)
		out = append(out, claircore.Package{})
		pkg := &out[i]
		var id int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Version,
			&pkg.Kind,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package: %w", err)
		}
		idStr := strconv.FormatInt(id, 10)
		pkg.ID = idStr
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
	}
	zlog.Debug(ctx).Int("count", len(out)).Msg("packages to filter")
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning packages: %w", err)
	}
	return out, nil
}
