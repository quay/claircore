package postgres

import (
	"sync"
	"testing"
	"unique"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

type latestVulnTestCase struct {
	TestName          string
	Updater           string
	VulnCount         int
	FirstOp, SecondOp *op
	Records           []*claircore.IndexRecord
}

type op struct {
	vulns        []*claircore.Vulnerability
	deletedVulns []string
}

func TestGetLatestVulnerabilities(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	cases := []latestVulnTestCase{
		{
			TestName:  "test initial op vuln still relevant",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "vi",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "vim",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "nano",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "vi",
						Source: &claircore.Package{
							Name:    "vi",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test vuln is overwritten not duped",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "BAD",
					},
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "sed",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "NOT AS BAD AS WE THOUGHT",
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "grep",
						Source: &claircore.Package{
							Name:    "grep",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test multiple vulns from same CVE",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "BAD",
					},
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "sed",
						},
						Severity: "REALLY BAD",
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "NOT AS BAD AS WE THOUGHT",
					},
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "sed",
						},
						Severity: "FINE",
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "grep",
						Source: &claircore.Package{
							Name:    "grep",
							Version: "v1.0.0",
						},
					},
				},
			},
		},

		{
			TestName:  "test two vulns same package different uo",
			Updater:   updater,
			VulnCount: 2,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-000",
						Package: &claircore.Package{
							Name: "python3",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "python3",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "python3-crypto",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "python3-urllib3",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "python3",
						Source: &claircore.Package{
							Name:    "python3",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test deleting vuln",
			Updater:   updater,
			VulnCount: 0,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-000",
						Package: &claircore.Package{
							Name: "jq",
						},
						Self: claircore.Alias{
							Space: unique.Make("CVE"),
							Name:  "000",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{"CVE-000"},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "jq-libs",
						},
						Self: claircore.Alias{
							Space: unique.Make("CVE"),
							Name:  "456",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "jq-docs",
						},
						Self: claircore.Alias{
							Space: unique.Make("CVE"),
							Name:  "789",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "jq",
						Source: &claircore.Package{
							Name:    "jq",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
	}

	// prepare DB
	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	// run test cases
	for _, tc := range cases {
		t.Run(tc.TestName, func(t *testing.T) {
			ctx := test.Logging(t, ctx)
			_, err := store.DeltaUpdateVulnerabilities(ctx, tc.Updater, driver.Fingerprint(uuid.New().String()), tc.FirstOp.vulns, tc.FirstOp.deletedVulns)
			if err != nil {
				t.Fatalf("failed to perform update for first op: %v", err)
			}
			_, err = store.DeltaUpdateVulnerabilities(ctx, tc.Updater, driver.Fingerprint(uuid.New().String()), tc.SecondOp.vulns, tc.SecondOp.deletedVulns)
			if err != nil {
				t.Fatalf("failed to perform update for second op: %v", err)
			}

			res, err := store.Get(ctx, tc.Records, datastore.GetOpts{})
			if err != nil {
				t.Fatalf("failed to get vulns: %v", err)
			}
			ct := 0
			for _, vs := range res {
				ct = ct + len(vs)
			}

			if ct != tc.VulnCount {
				t.Fatalf("got %d vulns, want %d", ct, tc.VulnCount)
			}
		})
	}
}

func TestUpdateVulnerabilitiesIterSinglePass(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	vulns := []*claircore.Vulnerability{
		{
			Updater: t.Name(),
			Name:    "CVE-2024-0001",
			Package: &claircore.Package{Name: "test-pkg"},
			Self:    claircore.Alias{Space: unique.Make("CVE"), Name: "CVE-2024-0001"},
			Aliases: []claircore.Alias{
				{Space: unique.Make("GHSA"), Name: "GHSA-xxxx-yyyy-zzzz"},
			},
		},
		{
			Updater: t.Name(),
			Name:    "CVE-2024-0002",
			Package: &claircore.Package{Name: "test-pkg-2"},
			Self:    claircore.Alias{Space: unique.Make("CVE"), Name: "CVE-2024-0002"},
			Aliases: []claircore.Alias{
				{Space: unique.Make("GHSA"), Name: "GHSA-aaaa-bbbb-cccc"},
			},
		},
	}

	// Single-pass iterator: yields data only on the first call, mimicking
	// jsonblob.RecordIter which streams from a compressed file.
	var once sync.Once
	singlePass := datastore.VulnerabilityIter(func(yield func(*claircore.Vulnerability, error) bool) {
		once.Do(func() {
			for _, v := range vulns {
				if !yield(v, nil) {
					return
				}
			}
		})
	})

	_, err := store.UpdateVulnerabilitiesIter(ctx, t.Name(), driver.Fingerprint(uuid.New().String()), singlePass)
	if err != nil {
		t.Fatalf("UpdateVulnerabilitiesIter: %v", err)
	}

	var vulnCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vuln WHERE updater = $1`, t.Name()).Scan(&vulnCount); err != nil {
		t.Fatalf("counting vulns: %v", err)
	}
	if vulnCount != len(vulns) {
		t.Fatalf("vuln table has %d rows, want %d; single-pass iterator was likely exhausted before the main insertion loop", vulnCount, len(vulns))
	}

	var aliasCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM alias`).Scan(&aliasCount); err != nil {
		t.Fatalf("counting aliases: %v", err)
	}
	if aliasCount == 0 {
		t.Fatal("alias table has 0 rows")
	}
	t.Logf("vuln rows: %d, alias rows: %d", vulnCount, aliasCount)
}
