package postgres

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/test"
)

func Test_GetQueryBuilder_Deterministic_Args(t *testing.T) {
	const (
		preamble = `SELECT
		"id", "name", "description", "links", "severity", "package_name", "package_version",
		"package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name",
		"dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key",
		"repo_uri", "fixed_in_version", "updater"
		FROM "vuln"
		WHERE `
		both       = `((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND `
		noSource   = `(("package_name" = 'package-0') AND `
		onlySource = `((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND `
	)
	var table = []struct {
		// name of test
		name string
		// the expected query string returned
		expectedQuery string
		// the match expressions which contrain the query
		matchExps []driver.MatchConstraint
		dbFilter  bool
		// a method to returning the indexRecord for the getQueryBuilder method
		indexRecord func() *claircore.IndexRecord
	}{
		{
			name: "NoSource,id",
			expectedQuery: preamble + noSource +
				`("dist_id" = 'did-0'))`,
			matchExps: []driver.MatchConstraint{driver.DistributionDID},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				pkgs[0].Source = &claircore.Package{} // clear source field
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "id",
			expectedQuery: preamble + both +
				`("dist_id" = 'did-0'))`,
			matchExps: []driver.MatchConstraint{driver.DistributionDID},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "id,version",
			expectedQuery: preamble + both +
				`("dist_id" = 'did-0') AND
				("dist_version" = 'version-0'))`,
			matchExps: []driver.MatchConstraint{
				driver.DistributionDID,
				driver.DistributionVersion,
			},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "id,version,version_id",
			expectedQuery: preamble + both +
				`("dist_id" = 'did-0') AND
				("dist_version" = 'version-0') AND
				("dist_version_id" = 'version-id-0'))`,
			matchExps: []driver.MatchConstraint{
				driver.DistributionDID,
				driver.DistributionVersion,
				driver.DistributionVersionID,
			},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "id,version,version_id,version_code_name",
			expectedQuery: preamble + both +
				`("dist_id" = 'did-0') AND
				("dist_version" = 'version-0') AND
				("dist_version_id" = 'version-id-0') AND
				("dist_version_code_name" = 'version-code-name-0'))`,
			matchExps: []driver.MatchConstraint{
				driver.DistributionDID,
				driver.DistributionVersion,
				driver.DistributionVersionID,
				driver.DistributionVersionCodeName,
			},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "DatabaseFilter",
			expectedQuery: preamble + both +
				`(("version_kind" = '') AND
				vulnerable_range @> '{0,0,0,0,0,0,0,0,0,0}'::int[]))`,
			matchExps: []driver.MatchConstraint{},
			dbFilter:  true,
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
		{
			name: "DatabaseFilterPython",
			expectedQuery: preamble + both +
				`(("version_kind" = 'pep440') AND
				vulnerable_range @> '{0,1,20,3,0,0,0,0,0,0}'::int[]))`,
			matchExps: []driver.MatchConstraint{},
			dbFilter:  true,
			indexRecord: func() *claircore.IndexRecord {
				v, err := pep440.Parse("1.20.3")
				if err != nil {
					panic(err)
				}
				pkgs := test.GenUniquePackages(1)
				pkgs[0].NormalizedVersion = v.Version()
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
	}

	// This is safe to do because SQL doesn't care about what whitespace is
	// where.
	//
	// Also, it produces more intelligible diffs when things break.
	normalizeWhitespace := cmpopts.AcyclicTransformer("normalizeWhitespace", strings.Fields)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ir := tt.indexRecord()
			opts := vulnstore.GetOpts{
				Matchers:         tt.matchExps,
				VersionFiltering: tt.dbFilter,
			}
			query, err := buildGetQuery(ir, &opts)
			if err != nil {
				t.Fatalf("failed to create query: %v", err)
			}
			t.Logf("got:\n%s", query)
			if !cmp.Equal(query, tt.expectedQuery, normalizeWhitespace) {
				t.Fatalf("%v", cmp.Diff(tt.expectedQuery, query, normalizeWhitespace))
			}
		})
	}
}
