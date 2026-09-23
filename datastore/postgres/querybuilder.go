package postgres

import (
	"fmt"
	"slices"
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
	return buildGetQueryCPEs(record, opts, recordCPEs(record))
}

// buildGetQueryCPEs is [buildGetQuery] with an explicit set of record CPEs.
// Each record CPE is OR'd into one attribute comparison.
func buildGetQueryCPEs(record *claircore.IndexRecord, opts *datastore.GetOpts, cpes []cpe.WFN) (string, error) {
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
		case driver.CPECompare:
			exps = append(exps, cpeCompareWFNs(cpes)...)
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

func recordCPEs(record *claircore.IndexRecord) []cpe.WFN {
	if record == nil || record.Repository == nil {
		return nil
	}
	if record.Repository.CPE.String() == "" {
		return nil
	}
	return []cpe.WFN{record.Repository.CPE}
}

// cpeCompareExpressions filters repo_name for one record CPE.
func cpeCompareExpressions(record *claircore.IndexRecord) []goqu.Expression {
	return cpeCompareWFNs(recordCPEs(record))
}

// cpeCompareWFNs filters repo_name to the record CPEs.
//
// Each CPE contributes one attribute comparison, OR'd with the others.
// A field matches when it is "*", equal to the record ignoring case, or
// contains a "*" or "?" glob. The version field also matches when the record
// version starts with the stored version, which is how VEX writes "4" for
// "4.13". The matcher still runs Compare, which drops globs this predicate
// keeps. Quoted colons still break split_part.
func cpeCompareWFNs(wfns []cpe.WFN) []goqu.Expression {
	var kept []cpe.WFN
	seenFS := map[string]struct{}{}
	for _, w := range wfns {
		fs := w.String()
		if fs == "" {
			continue
		}
		if _, ok := seenFS[fs]; ok {
			continue
		}
		seenFS[fs] = struct{}{}
		kept = append(kept, w)
	}
	if len(kept) == 0 {
		return nil
	}
	slices.SortFunc(kept, func(a, b cpe.WFN) int {
		return strings.Compare(a.String(), b.String())
	})
	arms := make([]goqu.Expression, len(kept))
	for i, w := range kept {
		arms[i] = cpeAttrSuperset(w)
	}
	return []goqu.Expression{goqu.Or(arms...)}
}

// cpeAttrSuperset matches when every repo_name attribute is "*", equal to w
// ignoring case, or a "*" / "?" glob. The version attribute also matches when
// the record version starts with the stored version. Globs are kept for the matcher.
func cpeAttrSuperset(w cpe.WFN) goqu.Expression {
	terms := make([]goqu.Expression, cpe.NumAttr)
	for a := range cpe.NumAttr {
		n := a + 3 // "cpe" and "2.3" occupy split_part indexes 1 and 2.
		field := "split_part(repo_name, ':', " + strconv.Itoa(n) + ")"
		val := strings.ToLower(w.Attr[a].String())
		match := goqu.L("lower("+field+") IN (?, '*')", val)
		if val == "*" {
			match = goqu.L("lower(" + field + ") IN ('*')")
		}
		term := []goqu.Expression{
			match,
			goqu.L("strpos(" + field + ", '*') > 0"),
			goqu.L("strpos(" + field + ", '?') > 0"),
		}
		if a == int(cpe.Version) {
			term = append(term, goqu.L("starts_with(?, "+field+")", w.Attr[cpe.Version].String()))
		}
		terms[a] = goqu.Or(term...)
	}
	return goqu.And(terms...)
}
