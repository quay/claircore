package postgres

import (
	"log"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/stretchr/testify/assert"
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
			expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_did" = $1) AND ("package_name" = $2))`,
		},
		// {
		// 	name:     "expect dist_name",
		// 	matchers: []driver.Matcher{driver.PackageDistributionName},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_name" = $1) AND ("package_name" = $2))`,
		// },
		// {
		// 	name:     "expect dist_version",
		// 	matchers: []driver.Matcher{driver.PackageDistributionVersion},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_version" = $1) AND ("package_name" = $2))`,
		// },
		// {
		// 	name:     "expect dist_version_code_name",
		// 	matchers: []driver.Matcher{driver.PackageDistributionVersionCodeName},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_version_code_name" = $1) AND ("package_name" = $2))`,
		// },
		// {
		// 	name:     "expect dist_version_id",
		// 	matchers: []driver.Matcher{driver.PackageDistributionVersionID},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_version_id" = $1) AND ("package_name" = $2))`,
		// },
		// {
		// 	name:     "expect dist_arch",
		// 	matchers: []driver.Matcher{driver.PackageDistributionArch},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_arch" = $1) AND ("package_name" = $2))`,
		// },
		// {
		// 	name:     "expect dist_did, dist_name",
		// 	matchers: []driver.Matcher{driver.PackageDistributionDID, driver.PackageDistributionName},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_did" = $1) AND ("dist_name" = $2) AND ("package_name" = $3))`,
		// },
		// {
		// 	name:     "expect dist_name, dist_did",
		// 	matchers: []driver.Matcher{driver.PackageDistributionName, driver.PackageDistributionDID},
		// 	expected: `SELECT "id", "name", "description", "links", "severity", "package_name", "package_version", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name", "dist_version_id", "arch", "fixed_in_version" FROM "vuln" WHERE (("dist_name" = $1) AND ("dist_did" = $2) AND ("package_name" = $3))`,
		// },
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
			assert.NoError(t, err)

			// assert.Equal(t, table.expected, q)
			log.Printf("%v", q)
		})
	}
}
