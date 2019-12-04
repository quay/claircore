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
		switch m {
		case driver.PackageDistributionDID:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_did": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionName:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_name": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionVersion:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_version": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionVersionCodeName:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_version_code_name": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionVersionID:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_version_id": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionArch:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_arch": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionCPE:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_cpe": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		case driver.PackageDistributionPrettyName:
			if _, ok := seen[m]; !ok {
				exps = append(exps, goqu.Ex{"dist_pretty_name": ""})
				seen[m] = struct{}{}
				deduped = append(deduped, m)
			}
		default:
			return "", nil, fmt.Errorf("was provided unknown matcher: %v", m)
		}
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
