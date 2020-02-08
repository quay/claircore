package postgres

import (
	"fmt"

	"github.com/doug-martin/goqu/v8"
	_ "github.com/doug-martin/goqu/v8/dialect/postgres"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// getQueryBuilder validates a IndexRecord and creates a query string for vulnerability matching
func buildGetQuery(record *claircore.IndexRecord, matchers []driver.MatchConstraint) (string, error) {
	psql := goqu.Dialect("postgres")
	exps := []goqu.Expression{}
	// add Package.Name as first condition in query
	if record.Package.Name == "" {
		return "", fmt.Errorf("IndexRecord must provide a Package.Name")
	}
	exps = append(exps, goqu.Ex{"package_name": record.Package.Name})

	// if package has source conver first exp to an OR statement
	if record.Package.Source.Name != "" {
		or := goqu.Or(
			goqu.Ex{"package_name": record.Package.Name},
			goqu.Ex{"package_name": record.Package.Source.Name},
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
		default:
			return "", fmt.Errorf("was provided unknown matcher: %v", m)
		}
		exps = append(exps, ex)
		seen[m] = struct{}{}
	}

	query := psql.Select(
		"id",
		"name",
		"description",
		"links",
		"severity",
		"package_name",
		"package_version",
		"package_kind",
		"dist_id",
		"dist_name",
		"dist_version",
		"dist_version_code_name",
		"dist_version_id",
		"dist_arch",
		"dist_cpe",
		"dist_pretty_name",
		"repo_name",
		"repo_key",
		"repo_uri",
		"fixed_in_version",
		"updater",
	).From("vuln").Where(exps...)

	sql, _, err := query.ToSQL()
	return sql, err
}
