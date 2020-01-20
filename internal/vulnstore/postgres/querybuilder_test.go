package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

func Test_GetQueryBuilder_Deterministic_Args(t *testing.T) {
	var table = []struct {
		// name of test
		name string
		// the expected query string returned
		expectedQuery string
		// the match expressions which contrain the query
		matchExps []driver.MatchConstraint
		// a method to returning the indexRecord for the getQueryBuilder method
		indexRecord func() *claircore.IndexRecord
	}{
		{
			name:          "No source package constrained by dist_id",
			expectedQuery: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version", "updater" FROM "vuln" WHERE (("package_name" = 'package-0') AND ("dist_id" = 'did-0'))`,
			matchExps:     []driver.MatchConstraint{driver.DistributionDID},
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
			name:          "Source package constrained by dist_id",
			expectedQuery: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version", "updater" FROM "vuln" WHERE ((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND ("dist_id" = 'did-0'))`,
			matchExps:     []driver.MatchConstraint{driver.DistributionDID},
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
			name:          "Source package constrained by dist_id",
			expectedQuery: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version", "updater" FROM "vuln" WHERE ((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND ("dist_id" = 'did-0') AND ("dist_version" = 'version-0'))`,
			matchExps:     []driver.MatchConstraint{driver.DistributionDID, driver.DistributionVersion},
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
			name:          "Source package constrained by dist_id",
			expectedQuery: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version", "updater" FROM "vuln" WHERE ((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND ("dist_id" = 'did-0') AND ("dist_version" = 'version-0') AND ("dist_version_id" = 'version-id-0'))`,
			matchExps:     []driver.MatchConstraint{driver.DistributionDID, driver.DistributionVersion, driver.DistributionVersionID},
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
			name:          "Source package constrained by dist_id",
			expectedQuery: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version", "updater" FROM "vuln" WHERE ((("package_name" = 'package-0') OR ("package_name" = 'source-package-0')) AND ("dist_id" = 'did-0') AND ("dist_version" = 'version-0') AND ("dist_version_id" = 'version-id-0') AND ("dist_version_code_name" = 'version-code-name-0'))`,
			matchExps:     []driver.MatchConstraint{driver.DistributionDID, driver.DistributionVersion, driver.DistributionVersionID, driver.DistributionVersionCodeName},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				dists := test.GenUniqueDistributions(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
				}
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ir := tt.indexRecord()
			query, err := buildGetQuery(ir, tt.matchExps)
			if err != nil {
				t.Fatalf("failed to create query: %v", err)
			}
			if !cmp.Equal(query, tt.expectedQuery) {
				t.Fatalf("%v", cmp.Diff(tt.expectedQuery, query))
			}
		})
	}
}
