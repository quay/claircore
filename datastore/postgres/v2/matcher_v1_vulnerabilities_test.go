package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres/v2"
)

func TestGet(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	cfg := pgtest.TestMatcherDB(ctx, t)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ref := uuid.New()
	if _, err := pool.Exec(ctx, `SELECT GetTestSetup(10, 'test', $1);`, ref); err != nil {
		t.Fatal(err)
	}
	store, err := NewMatcherV1(ctx, cfg, WithMigrations)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	tt := []getTestcase{
		{
			Name: "MatchName",
			IndexRecord: []*claircore.IndexRecord{
				{Package: &claircore.Package{ID: "0", Name: `package_0`}},
			},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 9
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchSourceName",
			IndexRecord: []*claircore.IndexRecord{
				{Package: &claircore.Package{ID: "0", Name: `none`, Source: &claircore.Package{ID: "1", Name: `package_0`}}},
			},
			Constraints: []driver.MatchConstraint{driver.PackageSourceName},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 1
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchModule",
			IndexRecord: []*claircore.IndexRecord{
				{Package: &claircore.Package{ID: "pkg1", Name: `package_0`, Module: `module_1`}},
				{Package: &claircore.Package{ID: "pkg2", Name: `package_0`, Module: `module_2`}},
				{Package: &claircore.Package{ID: "pkg3", Name: `package_0`, Module: `module_3`}},
				{Package: &claircore.Package{ID: "pkg0", Name: `package_0`, Module: `module_0`}},
			},
			Constraints: []driver.MatchConstraint{driver.PackageModule},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range []string{"pkg0", "pkg1", "pkg2", "pkg3"} {
					got, want := len(res[id]), 1
					t.Logf("%v: got: %d results, want: %d results", id, got, want)
					if got != want {
						t.Fail()
					}
				}
			},
		},
		{
			Name: "MatchDistributionID",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{DID: "distribution_1"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{DID: "distribution_2"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionDID},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 2
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionName",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Name: "Test"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionName},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 7
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionVersion",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "1"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "2"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "4"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "5"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "6"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "8"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Version: "9"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionVersion},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 7
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionVersionID",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "1"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "2"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "4"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "5"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "6"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "8"},
				},
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionID: "9"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionVersionID},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 7
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionVersionCodeName",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{VersionCodeName: "Chicago"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionVersionCodeName},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 7
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionArch",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{Arch: "aarch64"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionArch},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 2
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionCPE",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{CPE: cpe.MustUnbind("cpe:2.3" + strings.Repeat(":*", 11))},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionCPE},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 7
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchDistributionPrettyName",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:      &claircore.Package{ID: "0", Name: `package_0`},
					Distribution: &claircore.Distribution{PrettyName: "Test 1"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.DistributionPrettyName},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 1
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
		{
			Name: "MatchRepositoryName",
			IndexRecord: []*claircore.IndexRecord{
				{
					Package:    &claircore.Package{ID: "0", Name: `package_0`},
					Repository: &claircore.Repository{Name: "repository_1"},
				},
				{
					Package:    &claircore.Package{ID: "0", Name: `package_0`},
					Repository: &claircore.Repository{Name: "repository_4"},
				},
			},
			Constraints: []driver.MatchConstraint{driver.RepositoryName},
			Check: func(t *testing.T, res map[string][]*claircore.Vulnerability, err error) {
				if err != nil {
					t.Fatal(err)
				}
				got, want := len(res["0"]), 2
				t.Logf("got: %d results, want: %d results", got, want)
				if got != want {
					t.Fail()
				}
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, store))
	}
}

type getTestcase struct {
	Name        string
	IndexRecord []*claircore.IndexRecord
	Constraints []driver.MatchConstraint
	Check       func(*testing.T, map[string][]*claircore.Vulnerability, error)
}

func (tc getTestcase) Run(ctx context.Context, store *MatcherV1) func(*testing.T) {
	opts := datastore.MatcherV1VulnerabilityGetOpts{
		Matchers: tc.Constraints,
	}
	return func(t *testing.T) {
		t.Helper()
		ctx := zlog.Test(ctx, t)
		res, err := store.Get(ctx, tc.IndexRecord, opts)
		tc.Check(t, res, err)
		if t.Failed() {
			t.Logf("result: %s", cmp.Diff(nil, res))
			t.Logf("error: %v", err)
		}
	}
}

type latestTestCase struct {
	Vulnerable int
	Ops        [][]*claircore.Vulnerability
	Records    []*claircore.IndexRecord
}

// TestLatestVulns checks that only the latest update operations are considered
// when querying for vulnerabilities.
func TestLatestVulns(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	cases := []latestTestCase{
		{
			Vulnerable: 2,
			Ops: [][]*claircore.Vulnerability{
				{
					{
						Updater: "test-updater",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v2.0.0",
							Kind:    "binary",
						},
					},
				},
				{
					{
						Updater: "test-updater2",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v3.0.0",
							Kind:    "binary",
						},
					},
					{
						Updater: "test-updater2",
						Package: &claircore.Package{
							Name:    "vi",
							Version: "v3.1.0",
							Kind:    "binary",
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

	cfg := pgtest.TestMatcherDB(ctx, t)
	store, err := NewMatcherV1(ctx, cfg, WithMigrations)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, tc := range cases {
		for _, op := range tc.Ops {
			_, err := store.UpdateVulnerabilities(ctx, updater, driver.Fingerprint(uuid.New().String()), op)
			if err != nil {
				t.Fatalf("failed to perform update for first op: %v", err)
			}
		}

		res, err := store.Get(ctx, tc.Records, datastore.MatcherV1VulnerabilityGetOpts{})
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
