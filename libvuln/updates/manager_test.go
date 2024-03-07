package updates

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestDeltaUpdates(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	facs := map[string]driver.UpdaterSetFactory{
		"delta": &Factory{
			vulnGetter: &vulnGetter{
				testVulns: testVulns,
			},
		},
	}

	pool := pgtest.TestMatcherDB(ctx, t)
	store := postgres.NewMatcherStore(pool)

	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer locks.Close(ctx)

	// Using default client here as a non-nil client is an error,
	// it's never used.
	mgr, err := NewManager(ctx, store, locks, http.DefaultClient, WithFactories(facs))
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, tc := range testVulns {
		t.Run(tc.testName, func(t *testing.T) {
			// force update
			if err := mgr.Run(ctx); err != nil {
				t.Fatalf("%v", err)
			}

			vulns, err := getLatestVulnerabilities(ctx, pool, "test/delta/updater")
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(vulns) != tc.expectedNumber {
				t.Fatalf("expecting %d vuln but got %d", tc.expectedNumber, len(vulns))
			}
		})
	}

	vulns, err := getLatestVulnerabilities(ctx, pool, "test/delta/updater")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !cmp.Equal(vulns, finalVulns,
		cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID"), // Depends on the DB
		cmpopts.SortSlices(func(a, b interface{}) bool {
			return a.(*claircore.Vulnerability).Name < b.(*claircore.Vulnerability).Name
		})) {
		t.Error(cmp.Diff(vulns, finalVulns))
	}
}

var _ driver.DeltaUpdater = (*testUpdater)(nil)
var _ driver.Updater = (*testUpdater)(nil)

type testUpdater struct {
	vulnGetter *vulnGetter
}

func (tu *testUpdater) Name() string {
	return "test/delta/updater"
}

// DeltaFetch signals to the manager that we want to use DeltaFetch and store.DeltaUpdateVulnerabilities.
func (tu *testUpdater) Fetch(context.Context, driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	// NOOP
	return nil, "", nil
}

func (tu *testUpdater) Parse(ctx context.Context, vulnUpdates io.ReadCloser) ([]*claircore.Vulnerability, error) {
	// NOOP
	return nil, nil
}

func (tu *testUpdater) DeltaParse(ctx context.Context, vulnUpdates io.ReadCloser) ([]*claircore.Vulnerability, []string, error) {
	newVulns := tu.vulnGetter.Get()
	return newVulns.vulns, []string{}, nil
}

type Factory struct {
	vulnGetter *vulnGetter
}

func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	return nil
}

func (f *Factory) UpdaterSet(ctx context.Context) (s driver.UpdaterSet, err error) {
	s = driver.NewUpdaterSet()
	s.Add(&testUpdater{
		vulnGetter: f.vulnGetter,
	})
	return s, nil
}

type vulnGetter struct {
	testVulns []*fetchedVulns
	idx       int
}

func (vg *vulnGetter) Get() *fetchedVulns {
	if vg.idx+1 > len(vg.testVulns) {
		return nil
	}
	defer func() { vg.idx++ }()
	return vg.testVulns[vg.idx]
}

type fetchedVulns struct {
	vulns          []*claircore.Vulnerability
	expectedNumber int
	testName       string
}

var testVulns = []*fetchedVulns{
	{
		testName: "initial vuln",
		vulns: []*claircore.Vulnerability{
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:123",
				Description:        "bad things",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:123 https://moreprobs.io/CVE-2023:123",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
		},
		expectedNumber: 1,
	},
	{
		testName: "same vuln desc updated",
		vulns: []*claircore.Vulnerability{
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:123",
				Description:        "worse things",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:123 https://moreprobs.io/CVE-2023:123",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
		},
		expectedNumber: 1,
	},
	{
		testName: "two new vulns",
		vulns: []*claircore.Vulnerability{
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:456",
				Description:        "problems",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:456 https://moreprobs.io/CVE-2023:456",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:789",
				Description:        "problems again",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:789 https://moreprobs.io/CVE-2023:789",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
		},
		expectedNumber: 3,
	},
	{
		testName: "two updated one new",
		vulns: []*claircore.Vulnerability{
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:456",
				Description:        "problems 2",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:456 https://moreprobs.io/CVE-2023:456",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:789",
				Description:        "problems again",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:789 https://moreprobs.io/CVE-2023:789",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
			{
				Updater:            "test/delta/updater",
				Name:               "CVE-2023:101112",
				Description:        "problems again",
				Issued:             time.Time{},
				Links:              "https://ohno.com/CVE-2023:101112 https://moreprobs.io/CVE-2023:101112",
				Severity:           "Very Medium",
				NormalizedSeverity: claircore.Medium,
				Package: &claircore.Package{
					Name: "blah",
				},
			},
		},
		expectedNumber: 4,
	},
}

var finalVulns = []*claircore.Vulnerability{
	{
		Updater:            "test/delta/updater",
		Name:               "CVE-2023:123",
		Description:        "worse things",
		Issued:             time.Time{},
		Links:              "https://ohno.com/CVE-2023:123 https://moreprobs.io/CVE-2023:123",
		Severity:           "Very Medium",
		NormalizedSeverity: claircore.Medium,
		Package: &claircore.Package{
			Name: "blah",
		},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{},
	},
	{
		Updater:            "test/delta/updater",
		Name:               "CVE-2023:456",
		Description:        "problems 2",
		Issued:             time.Time{},
		Links:              "https://ohno.com/CVE-2023:456 https://moreprobs.io/CVE-2023:456",
		Severity:           "Very Medium",
		NormalizedSeverity: claircore.Medium,
		Package: &claircore.Package{
			Name: "blah",
		},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{},
	},
	{
		Updater:            "test/delta/updater",
		Name:               "CVE-2023:789",
		Description:        "problems again",
		Issued:             time.Time{},
		Links:              "https://ohno.com/CVE-2023:789 https://moreprobs.io/CVE-2023:789",
		Severity:           "Very Medium",
		NormalizedSeverity: claircore.Medium,
		Package: &claircore.Package{
			Name: "blah",
		},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{},
	},
	{
		Updater:            "test/delta/updater",
		Name:               "CVE-2023:101112",
		Description:        "problems again",
		Issued:             time.Time{},
		Links:              "https://ohno.com/CVE-2023:101112 https://moreprobs.io/CVE-2023:101112",
		Severity:           "Very Medium",
		NormalizedSeverity: claircore.Medium,
		Package: &claircore.Package{
			Name: "blah",
		},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{},
	},
}

func getLatestVulnerabilities(ctx context.Context, pool *pgxpool.Pool, updater string) ([]*claircore.Vulnerability, error) {
	query := `
		SELECT 
			"vuln"."id",
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
			"vuln"."updater"
		FROM
			"vuln"
			INNER JOIN "uo_vuln" ON ("vuln"."id" = "uo_vuln"."vuln")
			INNER JOIN "latest_update_operations" ON (
			"latest_update_operations"."id" = "uo_vuln"."uo"
			) 
		WHERE 
			(
			"latest_update_operations"."kind" = 'vulnerability'
			)
		AND
			(
			"vuln"."updater" = $1
			)
	`
	results := []*claircore.Vulnerability{}
	rows, err := pool.Query(ctx, query, updater)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// unpack all returned rows into claircore.Vulnerability structs
	for rows.Next() {
		// fully allocate vuln struct
		v := &claircore.Vulnerability{
			Package: &claircore.Package{},
			Dist:    &claircore.Distribution{},
			Repo:    &claircore.Repository{},
		}

		var id int64
		err := rows.Scan(
			&id,
			&v.Name,
			&v.Description,
			&v.Issued,
			&v.Links,
			&v.Severity,
			&v.NormalizedSeverity,
			&v.Package.Name,
			&v.Package.Version,
			&v.Package.Module,
			&v.Package.Arch,
			&v.Package.Kind,
			&v.Dist.DID,
			&v.Dist.Name,
			&v.Dist.Version,
			&v.Dist.VersionCodeName,
			&v.Dist.VersionID,
			&v.Dist.Arch,
			&v.Dist.CPE,
			&v.Dist.PrettyName,
			&v.ArchOperation,
			&v.Repo.Name,
			&v.Repo.Key,
			&v.Repo.URI,
			&v.FixedInVersion,
			&v.Updater,
		)
		v.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %v", err)
		}
		results = append(results, v)
	}

	return results, nil
}
