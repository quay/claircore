package postgres

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/doug-martin/goqu/v8"
	_ "github.com/doug-martin/goqu/v8/dialect/postgres"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// getQueryBuilder validates a IndexRecord and creates a query string for vulnerability matching
func buildGetQuery(record *claircore.IndexRecord, opts *vulnstore.GetOpts) (string, error) {
	matchers := opts.Matchers
	psql := goqu.Dialect("postgres")
	exps := []goqu.Expression{}

	// Add package name as first condition in query.
	if record.Package.Name == "" {
		return "", fmt.Errorf("IndexRecord must provide a Package.Name")
	}
	exps = append(exps, goqu.Ex{"package_name": record.Package.Name})

	// If the package has a source, convert the first expression to an OR.
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
	if err != nil {
		log.Debug().
			Err(err).
			Msg("error generating sql")
	}
	return sql, nil
}
