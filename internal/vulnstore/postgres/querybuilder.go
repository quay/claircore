package postgres

import (
	"fmt"

	"github.com/doug-martin/goqu/v8"
	_ "github.com/doug-martin/goqu/v8/dialect/postgres"

	"github.com/quay/claircore/libvuln/driver"
)

// getBuilder returns a query suitable for being prepared.
// the bindvars in the resulting string will be in the same order as the provided matchers array.
// if the matchers array contains duplicates they are ignored.
// see tests for what queries will look like and to further understand determinism
func getBuilder(matchers []driver.MatchExp) (string, []driver.MatchExp, error) {
	psql := goqu.Dialect("postgres")

	// creating an array of expressions will keep the order
	// of bindvars in the prepared statement deterministic.
	// so the caller knows where to put the arguments
	exps := []goqu.Expression{}

	// do not allow duplicates but retain ordering.
	seen := make(map[driver.MatchExp]struct{})
	deduped := []driver.MatchExp{}

	// currently we always search for vulnerabilities matching either a package's Source
	// name or the Binary name.
	pkgExt := goqu.Or(
		goqu.Ex{
			"package_name": "",
		},
		goqu.Ex{
			"package_name": "",
		},
	)
	exps = append(exps, pkgExt)

	for _, m := range matchers {
		if _, ok := seen[m]; ok {
			continue
		}
		var ex goqu.Ex
		switch m {
		case driver.PackageName: // ???
			//ex = goqu.Ex{"package_name": ""}
			continue
		case driver.PackageSourceName: // ???
			//ex = goqu.Ex{"package_name": ""}
			continue
		case driver.DistributionDID:
			ex = goqu.Ex{"dist_did": ""}
		case driver.DistributionName:
			ex = goqu.Ex{"dist_name": ""}
		case driver.DistributionVersion:
			ex = goqu.Ex{"dist_version": ""}
		case driver.DistributionVersionCodeName:
			ex = goqu.Ex{"dist_version_code_name": ""}
		case driver.DistributionVersionID:
			ex = goqu.Ex{"dist_version_id": ""}
		case driver.DistributionArch:
			ex = goqu.Ex{"dist_arch": ""}
		case driver.DistributionCPE:
			ex = goqu.Ex{"dist_cpe": ""}
		case driver.DistributionPrettyName:
			ex = goqu.Ex{"dist_pretty_name": ""}
		default:
			return "", nil, fmt.Errorf("was provided unknown matcher: %v", m)
		}
		exps = append(exps, ex)
		seen[m] = struct{}{}
		deduped = append(deduped, m)
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
	).From("vuln").Where(exps...).Prepared(true)

	sql, _, err := query.ToSQL()
	return sql, deduped, err
}
