package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/libvuln/driver"
)

func Test_GetBuilder_Deterministic_Arguments(t *testing.T) {
	var tt = []struct {
		name     string
		matchers []driver.MatchExp
		expected string
	}{
		{
			name:     "expect dist_did",
			matchers: []driver.MatchExp{driver.DistributionDID},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE ((("package_name" = $1) OR ("package_name" = $2)) AND ("dist_did" = $3))`,
		},
		{
			name:     "expect dist_did, dist_name",
			matchers: []driver.MatchExp{driver.DistributionDID, driver.DistributionName},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE ((("package_name" = $1) OR ("package_name" = $2)) AND ("dist_did" = $3) AND ("dist_name" = $4))`,
		},
		{
			name:     "expect dist_name, dist_did",
			matchers: []driver.MatchExp{driver.DistributionName, driver.DistributionDID},
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "repo_name", "repo_key", "repo_uri", "fixed_in_version" FROM "vuln" WHERE ((("package_name" = $1) OR ("package_name" = $2)) AND ("dist_name" = $3) AND ("dist_did" = $4))`,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			q, _, err := getBuilder(table.matchers)
			if err != nil {
				t.Fatalf("failed to build query: %v", err)
			}

			if !cmp.Equal(table.expected, q) {
				t.Fatalf("%v", cmp.Diff(table.expected, q))
			}
		})
	}
}
