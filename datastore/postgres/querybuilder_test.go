package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestGetQueryBuilderDeterministicArgs(t *testing.T) {
	const (
		preamble = `SELECT
		"vuln"."id", "name", "description", "issued", "links", "severity", "normalized_severity", "package_name", "package_version",
		"package_module", "package_arch", "package_kind", "dist_id", "dist_name", "dist_version", "dist_version_code_name",
		"dist_version_id", "dist_arch", "dist_cpe", "dist_pretty_name", "arch_operation", "repo_name", "repo_key",
		"repo_uri", "fixed_in_version", "vuln"."updater"
		FROM "vuln" INNER JOIN "uo_vuln" ON ("vuln"."id" = "uo_vuln"."vuln")
		INNER JOIN "latest_update_operations" ON ("latest_update_operations"."id" = "uo_vuln"."uo")
		WHERE `
		epilogue = ` AND ("latest_update_operations"."kind" = 'vulnerability'))`
		both     = `(((("package_name" = 'package-0') AND ("package_kind" = 'binary')) OR (("package_name" = 'source-package-0') AND ("package_kind" = 'source'))) AND `
		noSource = `((("package_name" = 'package-0') AND  ("package_kind" = 'binary')) AND `
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
				`("dist_id" = 'did-0')` + epilogue,
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
				`("dist_id" = 'did-0')` + epilogue,
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
				("dist_version" = 'version-0')` + epilogue,
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
				("dist_version_id" = 'version-id-0')` + epilogue,
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
				("dist_version_code_name" = 'version-code-name-0')` + epilogue,
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
				vulnerable_range @> '{0,0,0,0,0,0,0,0,0,0}'::int[])` + epilogue,
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
				vulnerable_range @> '{0,1,20,3,0,0,0,0,0,0}'::int[])` + epilogue,
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
		{
			name: "module-filter",
			expectedQuery: preamble + noSource +
				`("package_module" = 'module:0')` + epilogue,
			matchExps: []driver.MatchConstraint{driver.PackageModule},
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
			name: "repo_name",
			expectedQuery: preamble + noSource +
				`("repo_name" = 'repository-0')` + epilogue,
			matchExps: []driver.MatchConstraint{driver.RepositoryName},
			indexRecord: func() *claircore.IndexRecord {
				pkgs := test.GenUniquePackages(1)
				pkgs[0].Source = &claircore.Package{} // clear source field
				dists := test.GenUniqueDistributions(1)
				repos := test.GenUniqueRepositories(1)
				return &claircore.IndexRecord{
					Package:      pkgs[0],
					Distribution: dists[0],
					Repository:   repos[0],
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
			opts := datastore.GetOpts{
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

type testCase struct {
	Vulnerable int
	Ops        [][]*claircore.Vulnerability
	Records    []*claircore.IndexRecord
}

// TestLatestVulns checks that only the lastest update operations are
// considered when querying for vulns
func TestLatestVulns(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	cases := []testCase{
		{
			Vulnerable: 2,
			Ops: [][]*claircore.Vulnerability{
				{
					{
						Updater: "test-updater",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v2.0.0",
						},
					},
				},
				{
					{
						Updater: "test-updater2",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v3.0.0",
						},
					},
					{
						Updater: "test-updater2",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v3.1.0",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:   "1",
						Name: "vi",
						Source: &claircore.Package{
							Name:    "vi",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
	}

	pool := pgtest.TestMatcherDB(ctx, t)
	ctx, done := context.WithCancel(ctx)
	defer done()
	store := NewMatcherStore(pool)

	for _, tc := range cases {
		for _, op := range tc.Ops {
			_, err := store.UpdateVulnerabilities(ctx, updater, driver.Fingerprint(uuid.New().String()), op)
			if err != nil {
				t.Fatalf("failed to perform update for first op: %v", err)
			}
		}

		res, err := store.Get(ctx, tc.Records, datastore.GetOpts{})
		if err != nil {
			t.Fatalf("failed to get vulnerabilities: %v", err)
		}
		vulns := []*claircore.Vulnerability{}
		for _, vs := range res {
			vulns = append(vulns, vs...)
		}
		if len(vulns) != tc.Vulnerable {
			t.Fatalf("wrong number of vulns, got %d want %d", len(vulns), tc.Vulnerable)
		}
	}
}
