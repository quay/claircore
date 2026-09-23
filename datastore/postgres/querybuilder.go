package postgres

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/doug-martin/goqu/v8"
	_ "github.com/doug-martin/goqu/v8/dialect/postgres"
	"github.com/doug-martin/goqu/v8/exp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/cpe"
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
		goqu.Ex{"package_kind": wart.StringFromPackageKind(record.Package.Kind)},
	)
	exps = append(exps, packageQuery)

	// If the package has a source, convert the first expression to an OR.
	if record.Package.Source != nil && record.Package.Source.Name != "" {
		sourcePackageQuery := goqu.And(
			goqu.Ex{"package_name": record.Package.Source.Name},
			goqu.Ex{"package_kind": wart.StringFromPackageKind(record.Package.Source.Kind)},
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
		case driver.RepositoryKey:
			ex = goqu.Ex{"repo_key": record.Repository.Key}
		case driver.HasFixedInVersion:
			ex = goqu.Ex{"fixed_in_version": goqu.Op{exp.NeqOp.String(): ""}}
		case driver.CPESubstring:
			exps = append(exps, cpeSubstringExpressions(record)...)
			seen[m] = struct{}{}
			continue
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
		for i := range 10 {
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
	exps = append(exps, goqu.I("latest_update_operations.kind").Eq("vulnerability"))

	query := psql.Select(
		"vuln.id",
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
		"vuln.updater",
		"vuln.not_vulnerable",
	).From("vuln").
		Join(goqu.I("uo_vuln"), goqu.On(goqu.Ex{"vuln.id": goqu.I("uo_vuln.vuln")})).
		Join(goqu.I("latest_update_operations"), goqu.On(goqu.Ex{"latest_update_operations.id": goqu.I("uo_vuln.uo")})).
		Where(exps...)

	sql, _, err := query.ToSQL()
	if err != nil {
		return "", err
	}
	return sql, nil
}

// cpeSubstringExpressions filters repo_name to the record CPE's part/vendor/product
// prefix (indexable LIKE) then the SQL form of CPE substring match (starts_with + rtrim).
func cpeSubstringExpressions(record *claircore.IndexRecord) []goqu.Expression {
	if record == nil || record.Repository == nil {
		return nil
	}
	w := record.Repository.CPE
	fs := w.String()
	if fs == "" {
		return nil
	}
	var exps []goqu.Expression
	if prefix := cpeProductPrefix(w); prefix != "" {
		exps = append(exps, goqu.C("repo_name").Like(likeEscape(prefix)+"%"))
	}
	exps = append(exps, goqu.L("starts_with(?, rtrim(repo_name, ':*'))", fs))
	return exps
}

// cpeProductPrefix returns the formatted-string prefix through the last set
// part/vendor/product attribute, with a trailing colon. Product (or vendor)
// ANY stops one attribute earlier so LIKE still matches concrete names.
// The version header and attribute escaping come from [cpe.WFN.String].
func cpeProductPrefix(w cpe.WFN) string {
	fs := w.String()
	if fs == "" {
		return ""
	}
	last := -1
	for a := cpe.Part; a <= cpe.Product; a++ {
		if w.Attr[a].Kind != cpe.ValueSet {
			break
		}
		last = int(a)
	}
	if last < 0 {
		return ""
	}
	i := 0
	for a := cpe.Part; a <= cpe.Attribute(last); a++ {
		bound := ":" + w.Attr[a].String()
		j := strings.Index(fs[i:], bound)
		if j < 0 {
			return ""
		}
		i += j + len(bound)
	}
	return fs[:i] + ":"
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
