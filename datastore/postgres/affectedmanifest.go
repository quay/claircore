package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/doug-martin/goqu/v8"
	"github.com/jackc/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	_ "github.com/quay/claircore/matchers/defaults"
	"github.com/quay/claircore/matchers/registry"
)

var (
	// ErrVulnNotApplicable is returned if it is deemed that the vulnerability and the
	// matcher's Query method wouldn't return any matching IndexRecords.
	ErrVulnNotApplicable        = fmt.Errorf("vulnerability is not applicable")
	getAffectedManifestsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "datastore",
			Name:      "getaffectedmanifests_total",
			Help:      "Total number of database queries issued in the AffectedManifests method.",
		},
		[]string{"query"},
	)
	getAffectedManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "datastore",
			Name:      "getaffectedmanifests_duration_seconds",
			Help:      "The duration of all queries issued in the AffectedManifests method",
		},
		[]string{"query"},
	)
)

// queryBuilder takes a vulnerability and a matcher and constructs a SQL query
// to determine which manifest hashes are affected by the vulnerability given
// the matcher's constraints.
func queryBuilder(v *claircore.Vulnerability, m driver.Matcher) (string, error) {
	psql := goqu.Dialect("postgres")
	exps := []goqu.Expression{}
	packageQuery := goqu.Ex{"package.name": v.Package.Name}
	exps = append(exps, packageQuery)
	seen := make(map[driver.MatchConstraint]struct{})
	for _, m := range m.Query() {
		if _, ok := seen[m]; ok {
			continue
		}
		var ex goqu.Ex
		switch m {
		case driver.PackageModule:
			// It is possible for a matcher to specify a Package.Module constraint
			// and the Vulnerability.Package.Module is empty. This is different from
			// the other constraints.
			ex = goqu.Ex{"package.module": v.Package.Module}
		case driver.DistributionDID:
			if v.Dist.DID == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.did": v.Dist.DID}
		case driver.DistributionName:
			if v.Dist.Name == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.name": v.Dist.Name}
		case driver.DistributionVersionID:
			if v.Dist.VersionID == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.version_id": v.Dist.VersionID}
		case driver.DistributionVersion:
			if v.Dist.Version == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.version": v.Dist.Version}
		case driver.DistributionVersionCodeName:
			if v.Dist.VersionCodeName == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.version_code_name": v.Dist.VersionCodeName}
		case driver.DistributionPrettyName:
			if v.Dist.PrettyName == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.pretty_name": v.Dist.PrettyName}
		case driver.DistributionCPE:
			if v.Dist.CPE.String() == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.cpe": v.Dist.CPE}
		case driver.DistributionArch:
			if v.Dist.Arch == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"dist.arch": v.Dist.Arch}
		case driver.RepositoryName:
			if v.Repo.Name == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"repo.name": v.Repo.Name}
		case driver.RepositoryKey:
			if v.Repo.Key == "" {
				return "", ErrVulnNotApplicable
			}
			ex = goqu.Ex{"repo.key": v.Repo.Key}
		case driver.HasFixedInVersion:
			if v.FixedInVersion == "" {
				// No unpatched vulnerabilities wanted, vulnerability is not applicable.
				return "", ErrVulnNotApplicable
			}
		default:
			return "", fmt.Errorf("was provided unknown matcher: %v", m)
		}
		exps = append(exps, ex)
		seen[m] = struct{}{}
	}
	f, ok := m.(driver.VersionFilter)
	if ok && f.VersionAuthoritative() {
		kind, lower, upper := rangefmt(v.Range)
		if kind != nil {
			exps = append(exps, goqu.And(
				goqu.C("norm_kind").Eq(kind),
				goqu.L("VersionRange('"+lower+"','"+upper+"') @> package.norm_version"),
			))
		}
	}
	query := psql.Select(
		"manifest.hash",
		"package.name",
		"package.version",
		"package.kind",
		"package.norm_kind",
		"package.norm_version",
		"package.arch",
		goqu.COALESCE(goqu.I("dist.name"), ""),
		goqu.COALESCE(goqu.I("dist.did"), ""),
		goqu.COALESCE(goqu.I("dist.version"), ""),
		goqu.COALESCE(goqu.I("dist.version_code_name"), ""),
		goqu.COALESCE(goqu.I("dist.version_id"), ""),
		goqu.COALESCE(goqu.I("dist.arch"), ""),
		goqu.COALESCE(goqu.I("dist.cpe"), ""),
		goqu.COALESCE(goqu.I("dist.pretty_name"), ""),
		goqu.COALESCE(goqu.I("repo.name"), ""),
		goqu.COALESCE(goqu.I("repo.key"), ""),
		goqu.COALESCE(goqu.I("repo.uri"), ""),
		goqu.COALESCE(goqu.I("repo.cpe"), ""),
	).From("manifest_index").
		Join(goqu.I("package"), goqu.On(goqu.Ex{"manifest_index.package_id": goqu.I("package.id")})).
		LeftJoin(goqu.I("repo"), goqu.On(goqu.Ex{"manifest_index.repo_id": goqu.I("repo.id")})).
		LeftJoin(goqu.I("dist"), goqu.On(goqu.Ex{"manifest_index.dist_id": goqu.I("dist.id")})).
		Join(goqu.I("manifest"), goqu.On(goqu.Ex{"manifest_index.manifest_id": goqu.I("manifest.id")})).
		Where(exps...)
	sql, _, err := query.ToSQL()
	if err != nil {
		return "", err
	}
	return sql, nil
}

// AffectedManifests returns a list of manifest hashes that are affected by the given vulnerability.
// It iterates over registered matcher factories, generating matchers and building SQL queries
// using the provided vulnerability. The function then executes these queries to retrieve affected
// manifests, filtering results based on vulnerability criteria.
func (s *IndexerStore) AffectedManifests(ctx context.Context, v claircore.Vulnerability) ([]claircore.Digest, error) {
	matcherFactories := registry.Registered()
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/AffectedManifests")
	mrs := map[string]struct{}{}
	out := []claircore.Digest{}
	for n, mf := range matcherFactories {
		ms, err := mf.Matcher(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create matchers from factory %s: %w", n, err)
		}
		for _, m := range ms {
			miQuery, err := queryBuilder(&v, m)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, ErrVulnNotApplicable):
				continue
			default:
				return nil, fmt.Errorf("error building query %w", err)
			}
			err = func() error {
				start := time.Now()
				rows, err := s.pool.Query(ctx, miQuery)
				switch {
				case errors.Is(err, nil):
				default:
					return fmt.Errorf("failed to query packages associated with vulnerability %q: %w", v.ID, err)
				}

				defer rows.Close()
				for rows.Next() {
					ir := &claircore.IndexRecord{
						Package:      &claircore.Package{},
						Repository:   &claircore.Repository{},
						Distribution: &claircore.Distribution{},
					}
					var (
						manifestDigest *claircore.Digest
						nVer           pgtype.Int4Array
						nKind          *string
					)
					err := rows.Scan(
						&manifestDigest,
						&ir.Package.Name,
						&ir.Package.Version,
						&ir.Package.Kind,
						&nKind,
						&nVer,
						&ir.Package.Arch,
						&ir.Distribution.Name,
						&ir.Distribution.DID,
						&ir.Distribution.Version,
						&ir.Distribution.VersionCodeName,
						&ir.Distribution.VersionID,
						&ir.Distribution.Arch,
						&ir.Distribution.CPE,
						&ir.Distribution.PrettyName,
						&ir.Repository.Name,
						&ir.Repository.Key,
						&ir.Repository.URI,
						&ir.Repository.CPE,
					)
					if err != nil {
						return fmt.Errorf("failed to scan index record: %w", err)
					}
					if nKind != nil {
						ir.Package.NormalizedVersion.Kind = *nKind
						if nVer.Status == pgtype.Present && len(nVer.Elements) > 0 {
							for i, n := range nVer.Elements {
								ir.Package.NormalizedVersion.V[i] = n.Int
							}
						}
					}
					if manifestDigest == nil {
						return errors.New("manifest digest is nil")
					}
					if _, ok := mrs[manifestDigest.String()]; ok {
						// We've already seen the manifest we don't need to
						// redo the work.
						continue
					}
					if !m.Filter(ir) {
						continue
					}
					var match bool
					f, ok := m.(driver.VersionFilter)
					if ok && f.VersionAuthoritative() {
						// We've already done the vulnerable checking in the database so
						// we don't need to call the Vulnerable() function.
						match = true
					} else {
						match, err = m.Vulnerable(ctx, ir, &v)
						if err != nil {
							return fmt.Errorf("error checking for if IndexRecord is vulnerable %w", err)
						}
					}
					if match {
						mrs[manifestDigest.String()] = struct{}{}
						out = append(out, *manifestDigest)
					}
				}
				getAffectedManifestsCounter.WithLabelValues("query_batch").Add(1)
				getAffectedManifestsDuration.WithLabelValues("query_batch").Observe(time.Since(start).Seconds())
				return nil
			}()
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
