package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore/libvuln/driver"
)

func Test_GetBuilder_Determinist_Arguments(t *testing.T) {
	var tt = []struct {
		name     string
		matchers []driver.MatchExp
		expected string
	}{
		{
			name:     "expect dist_did",
			matchers: []driver.MatchExp{driver.PackageDistributionDID},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_did" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_name",
			matchers: []driver.MatchExp{driver.PackageDistributionName},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_name" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_version",
			matchers: []driver.MatchExp{driver.PackageDistributionVersion},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_version" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_version_code_name",
			matchers: []driver.MatchExp{driver.PackageDistributionVersionCodeName},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_version_code_name" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_version_id",
			matchers: []driver.MatchExp{driver.PackageDistributionVersionID},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_version_id" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_arch",
			matchers: []driver.MatchExp{driver.PackageDistributionArch},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_arch" = $1) AND (("package_name" = $2) OR ("package_name" = $3)))`,
		},
		{
			name:     "expect dist_did, dist_name",
			matchers: []driver.MatchExp{driver.PackageDistributionDID, driver.PackageDistributionName},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_did" = $1) AND ("dist_name" = $2) AND (("package_name" = $3) OR ("package_name" = $4)))`,
		},
		{
			name:     "expect dist_name, dist_did",
			matchers: []driver.MatchExp{driver.PackageDistributionName, driver.PackageDistributionDID},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE (("dist_name" = $1) AND ("dist_did" = $2) AND (("package_name" = $3) OR ("package_name" = $4)))`,
		},
		// {
		// 	name: "expect dist_did, dist_name, dist_version",
		// 	matchers: []driver.Matcher{
		// 		driver.PackageDistributionDID,
		// 		driver.PackageDistributionName,
		// 		driver.PackageDistributionVersion,
		// 	},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_did" = $1) AND ("dist_name" = $2) AND ("dist_version" = $3) AND ("package_name" = $4))`,
		// },
		// {
		// 	name: "expect dist_name, dist_did, dist_version",
		// 	matchers: []driver.Matcher{
		// 		driver.PackageDistributionName,
		// 		driver.PackageDistributionDID,
		// 		driver.PackageDistributionVersion,
		// 	},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_name" = $1) AND ("dist_did" = $2) AND ("dist_version" = $3) AND ("package_name" = $4))`,
		// },
		// {
		// 	name: "expect dist_version, dist_did, dist_name",
		// 	matchers: []driver.Matcher{
		// 		driver.PackageDistributionVersion,
		// 		driver.PackageDistributionDID,
		// 		driver.PackageDistributionName,
		// 	},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_version" = $1) AND ("dist_did" = $2) AND ("dist_name" = $3) AND ("package_name" = $4))`,
		// },
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			q, _, err := getBuilder(table.matchers)
			if err != nil {
				t.Fatalf("failed to build query: %v", err)
			}

			// assert.Equal(t, table.expected, q)
			if !cmp.Equal(table.expected, q) {
				t.Fatalf("%v", cmp.Diff(table.expected, q))
			}
		})
	}
}
