package postgres

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/doug-martin/goqu/v8"
	_ "github.com/doug-martin/goqu/v8/dialect/postgres"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

// getQueryBuilder validates a IndexRecord and creates a query string for vulnerability matching
func buildGetQuery(record *claircore.IndexRecord, opts *datastore.GetOpts) (string, error) {
	matchers := opts.Matchers
	psql := goqu.Dialect("postgres")
	exps := []goqu.Expression{}

	// Add package name as first condition in query.
	if record.Package.Name == "" {
		return "", fmt.Errorf("IndexRecord must provide a Package.Name")
	}
	packageQuery := goqu.And(
		goqu.Ex{"package_name": record.Package.Name},
		goqu.Ex{"package_kind": record.Package.Kind},
	)
	exps = append(exps, packageQuery)

	// If the package has a source, convert the first expression to an OR.
	if record.Package.Source.Name != "" {
		sourcePackageQuery := goqu.And(
			goqu.Ex{"package_name": record.Package.Source.Name},
			goqu.Ex{"package_kind": record.Package.Source.Kind},
		)
		or := goqu.Or(
			packageQuery,
			sourcePackageQuery,
		)
		exps[0] = or
	}

	// add matchers
	seen := make(map[driver.MatchConstraint]struct{})
	for _, m := range matchers {
		if _, ok := seen[m]; ok {
			continue
		}
		var ex goqu.Ex
		switch m {
		case driver.PackageModule:
			ex = goqu.Ex{"package_module": record.Package.Module}
		case driver.DistributionDID:
			ex = goqu.Ex{"dist_id": record.Distribution.DID}
		case driver.DistributionName:
			ex = goqu.Ex{"dist_name": record.Distribution.Name}
		case driver.DistributionVersionID:
			ex = goqu.Ex{"dist_version_id": record.Distribution.VersionID}
		case driver.DistributionVersion:
			ex = goqu.Ex{"dist_version": record.Distribution.Version}
		case driver.DistributionVersionCodeName:
			ex = goqu.Ex{"dist_version_code_name": record.Distribution.VersionCodeName}
		case driver.DistributionPrettyName:
			ex = goqu.Ex{"dist_pretty_name": record.Distribution.PrettyName}
		case driver.DistributionCPE:
			ex = goqu.Ex{"dist_cpe": record.Distribution.CPE}
		case driver.DistributionArch:
			ex = goqu.Ex{"dist_arch": record.Distribution.Arch}
		case driver.RepositoryName:
			ex = goqu.Ex{"repo_name": record.Repository.Name}
		default:
			return "", fmt.Errorf("was provided unknown matcher: %v", m)
		}
		exps = append(exps, ex)
		seen[m] = struct{}{}
	}
	if opts.VersionFiltering {
		v := &record.Package.NormalizedVersion
		var lit strings.Builder
		b := make([]byte, 0, 16)
		lit.WriteString("'{")
		for i := 0; i < 10; i++ {
			if i != 0 {
				lit.WriteByte(',')
			}
			lit.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
		}
		lit.WriteString("}'::int[]")
		exps = append(exps, goqu.And(
			goqu.C("version_kind").Eq(v.Kind),
			goqu.L("vulnerable_range @> "+lit.String()),
		))
	}

	query := psql.Select(
		"id",
		"name",
		"description",
		"issued",
		"links",
		"severity",
		"normalized_severity",
		"package_name",
		"package_version",
		"package_module",
		"package_arch",
		"package_kind",
		"dist_id",
		"dist_name",
		"dist_version",
		"dist_version_code_name",
		"dist_version_id",
		"dist_arch",
		"dist_cpe",
		"dist_pretty_name",
		"arch_operation",
		"repo_name",
		"repo_key",
		"repo_uri",
		"fixed_in_version",
		"updater",
	).From("vuln").Where(exps...)

	sql, _, err := query.ToSQL()
	if err != nil {
		return "", err
	}
	return sql, nil
}
